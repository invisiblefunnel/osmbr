package osmbr_test

// The differential oracle: for each decoder entry point, run the optimized
// implementation and the reference in reference_test.go over the same bytes and
// require that they agree.
//
// Agreement means two things:
//
//   - Identical error behaviour. Both must fail or both must succeed. The error
//     values themselves are not compared — osmbr wraps its errors with the name
//     of the enclosing message, which the reference has no equivalent for — but
//     whether an input is accepted is never allowed to differ.
//   - Identical output. When both accept an input, every decoded value must
//     match exactly, byte for byte on []byte fields.
//
// Decoded values are compared only when both sides accept the input. A decoder
// that reports an error is free to leave anything in the caller's buffers, and
// both of these leave partially decoded values there; nothing reads them.
//
// The functions here are shared by the fuzz targets in fuzz_test.go and by the
// table tests at the bottom of this file.

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"math"
	"reflect"
	"testing"
	"testing/iotest"

	"github.com/invisiblefunnel/osmbr"
)

// maxEntities bounds every collect loop below. A decoder that failed to
// terminate would otherwise hang the fuzzer instead of failing it, and no
// PrimitiveGroup can hold more entities than this from a fuzz-sized input.
const maxEntities = 1 << 16

// Bounds on how much inflation one input may cost.
//
// A zlib stream a few dozen bytes long can inflate to the 32 MiB a Blob is
// allowed, and a file mutated out of a small seed can hold dozens of them. The
// checks here inflate each blob several times over — once for the reference,
// again for the reused decompressor, again for SkipChecksum — so an input that
// looks tiny can cost gigabytes of inflation. Left unbounded that is enough for
// a single input to take tens of seconds, which does not just waste fuzzing
// time: the fuzzer gives up on the whole target with "context deadline
// exceeded" when a worker stops responding.
//
// So the expensive repeats are skipped once a payload gets large, and the
// file-level targets stop decoding blocks once an input has cost enough in
// total. What that gives up is the repeat checks on large payloads only: the
// reference comparison always runs, and the repeats are about buffer and
// inflater state, which a small payload exercises the same way. The 32 MiB
// boundary itself is covered exactly by the tests in decompress_test.go.
const (
	repeatDecompressLimit = 1 << 20
	inflateBudget         = 8 << 20
)

// errAgree reports a disagreement over whether input is valid. It returns true
// when the caller should stop, either because the two disagreed or because both
// failed and there are no values worth comparing.
func errAgree(t *testing.T, what string, input []byte, osmErr, refErr error) (stop bool) {
	t.Helper()
	switch {
	case osmErr == nil && refErr != nil:
		t.Errorf("%s: osmbr accepted input the reference rejected\n"+
			"  reference error: %v\n  input: %s", what, refErr, dumpBytes(input))
		return true
	case osmErr != nil && refErr == nil:
		t.Errorf("%s: osmbr rejected input the reference accepted\n"+
			"  osmbr error: %v\n  input: %s", what, osmErr, dumpBytes(input))
		return true
	default:
		return osmErr != nil
	}
}

// dumpBytes renders input as a Go byte-slice literal so a failure can be
// replayed directly.
func dumpBytes(b []byte) string {
	const max = 512
	trunc := ""
	if len(b) > max {
		trunc = fmt.Sprintf(" ...(truncated from %d bytes)", len(b))
		b = b[:max]
	}
	return fmt.Sprintf("%#v%s", b, trunc)
}

// eq compares one field of a decode result, naming it and the input on failure.
func eq(t *testing.T, what, field string, input []byte, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s: %s mismatch\n  osmbr:     %#v\n  reference: %#v\n  input: %s",
			what, field, got, want, dumpBytes(input))
	}
}

// --- BlockReader -----------------------------------------------------------

type diffBlock struct {
	Type   string
	Offset int64
	Blob   []byte
}

// diffBlockReader checks BlockReader's framing against refBlocks, and checks
// that Next, NextInto, and Reset all agree with each other.
func diffBlockReader(t *testing.T, data []byte) {
	t.Helper()

	got, osmErr := collectBlocksInto(t, data)

	refBlks, refErr := refBlocks(data)
	want := make([]diffBlock, 0, len(refBlks))
	for _, b := range refBlks {
		want = append(want, diffBlock{Type: b.Type, Offset: b.Offset, Blob: b.Blob})
	}

	// Whichever side stops first, the blocks both produced must be the same:
	// errors are sticky and reading stops at the first failure, so the shorter
	// run is a prefix of the longer one.
	for i := 0; i < len(got) && i < len(want); i++ {
		eq(t, "BlockReader", fmt.Sprintf("block[%d]", i), data, got[i], want[i])
	}
	if errAgree(t, "BlockReader", data, osmErr, refErr) {
		return
	}
	eq(t, "BlockReader", "block count", data, len(got), len(want))

	// Next and Blob must see exactly what NextInto returns.
	br := osmbr.NewBlockReader(bytes.NewReader(data))
	n := 0
	for ; br.Next(); n++ {
		if n >= len(got) {
			t.Errorf("BlockReader: Next produced more blocks than NextInto\n  input: %s",
				dumpBytes(data))
			break
		}
		eq(t, "BlockReader", fmt.Sprintf("Next block[%d]", n), data,
			diffBlock{Type: br.Type(), Offset: br.Offset(), Blob: br.Blob()}, got[n])
	}
	if n == len(got) && (br.Err() != nil) != (osmErr != nil) {
		t.Errorf("BlockReader: Next and NextInto disagree on error: %v vs %v\n  input: %s",
			br.Err(), osmErr, dumpBytes(data))
	}

	// Reset must leave a used reader — including one left holding a sticky
	// error — indistinguishable from a fresh one.
	br.Reset(bytes.NewReader(data))
	n = 0
	for ; br.Next(); n++ {
		if n >= len(got) {
			t.Errorf("BlockReader: Reset produced more blocks than NextInto\n  input: %s",
				dumpBytes(data))
			break
		}
		eq(t, "BlockReader", fmt.Sprintf("post-Reset block[%d]", n), data,
			diffBlock{Type: br.Type(), Offset: br.Offset(), Blob: br.Blob()}, got[n])
	}
	if n == len(got) && (br.Err() != nil) != (osmErr != nil) {
		t.Errorf("BlockReader: Reset changed error behaviour: %v vs %v\n  input: %s",
			br.Err(), osmErr, dumpBytes(data))
	}

	// A reader that hands back one byte at a time must produce the same blocks.
	// bytes.Reader never returns a short read, so it never exercises the
	// io.ReadFull calls doing their job; a network or gzip-wrapped reader would.
	br.Reset(iotest.OneByteReader(bytes.NewReader(data)))
	n = 0
	for ; br.Next(); n++ {
		if n >= len(got) {
			t.Errorf("BlockReader: one-byte reader produced more blocks\n  input: %s",
				dumpBytes(data))
			break
		}
		eq(t, "BlockReader", fmt.Sprintf("one-byte block[%d]", n), data,
			diffBlock{Type: br.Type(), Offset: br.Offset(), Blob: br.Blob()}, got[n])
	}
	if n == len(got) && (br.Err() != nil) != (osmErr != nil) {
		t.Errorf("BlockReader: one-byte reader changed error behaviour: %v vs %v\n  input: %s",
			br.Err(), osmErr, dumpBytes(data))
	}
}

// collectBlocksInto reads every block via NextInto, recycling one buffer the
// way a caller streaming a real file would.
func collectBlocksInto(t *testing.T, data []byte) ([]diffBlock, error) {
	t.Helper()
	var out []diffBlock
	br := osmbr.NewBlockReader(bytes.NewReader(data))
	for blob, ok := br.NextInto(nil); ok; blob, ok = br.NextInto(blob[:0]) {
		out = append(out, diffBlock{
			Type:   br.Type(),
			Offset: br.Offset(),
			Blob:   append([]byte(nil), blob...),
		})
		if len(out) > maxEntities {
			t.Fatalf("BlockReader produced more than %d blocks from %d bytes",
				maxEntities, len(data))
		}
	}
	return out, br.Err()
}

// --- Decompressor ----------------------------------------------------------

// recoveryProbePayload and recoveryProbe are a small valid zlib Blob used to
// check that a Decompressor is still usable after any blob at all.
//
// The probe goes down the zlib path deliberately: the inflater is the piece of
// state a failed decompress could leave behind, and it is reset rather than
// rebuilt on each call.
var (
	recoveryProbePayload = []byte("recovery probe")
	recoveryProbe        = func() []byte {
		var buf bytes.Buffer
		zw := zlib.NewWriter(&buf)
		if _, err := zw.Write(recoveryProbePayload); err != nil {
			panic(err)
		}
		if err := zw.Close(); err != nil {
			panic(err)
		}
		return zlibBlob(len(recoveryProbePayload), buf.Bytes())
	}()
)

// diffDecompress checks Decompressor.Decompress against refDecompress, which
// inflates with compress/zlib instead of driving flate directly.
func diffDecompress(t *testing.T, blob []byte) {
	t.Helper()

	var dec osmbr.Decompressor
	out, osmErr := dec.Decompress(blob)
	got := append([]byte(nil), out...)

	// Whatever that blob did, the decompressor has to survive it: one is kept
	// for a whole file, so a blob that poisoned it would take every later block
	// down with it. Run before the comparisons below, so it also covers the
	// blobs that failed.
	if probe, err := dec.Decompress(recoveryProbe); err != nil {
		t.Errorf("Decompress: decompressor unusable after this blob: %v\n  input: %s",
			err, dumpBytes(blob))
	} else if !bytes.Equal(probe, recoveryProbePayload) {
		t.Errorf("Decompress: decompressor damaged after this blob: probe gave %q\n  input: %s",
			probe, dumpBytes(blob))
	}

	want, refErr := refDecompress(blob)

	if errAgree(t, "Decompress", blob, osmErr, refErr) {
		return
	}
	if osmErr != nil {
		return
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Decompress: payload mismatch (osmbr %d bytes, reference %d bytes)\n  input: %s",
			len(got), len(want), dumpBytes(blob))
		return
	}

	// The two checks below inflate the blob again each, so they are skipped on
	// payloads large enough to make that expensive. See repeatDecompressLimit.
	if len(got) > repeatDecompressLimit {
		return
	}

	// One Decompressor reuses its output buffer and its inflater across blobs,
	// so the same blob must decode the same way the second time.
	out2, osmErr2 := dec.Decompress(blob)
	if osmErr2 != nil {
		t.Errorf("Decompress: reuse rejected a blob it accepted: %v\n  input: %s",
			osmErr2, dumpBytes(blob))
	} else if !bytes.Equal(out2, got) {
		t.Errorf("Decompress: reuse changed the payload\n  input: %s", dumpBytes(blob))
	}

	// SkipChecksum drops the Adler-32 verification and nothing else, so it may
	// accept a blob the default rejects but must never reject one the default
	// accepts, nor decode it differently.
	var skip osmbr.Decompressor
	skip.SkipChecksum = true
	out3, err3 := skip.Decompress(blob)
	if err3 != nil {
		t.Errorf("Decompress: SkipChecksum rejected an accepted blob: %v\n  input: %s",
			err3, dumpBytes(blob))
	} else if !bytes.Equal(out3, got) {
		t.Errorf("Decompress: SkipChecksum changed the payload\n  input: %s", dumpBytes(blob))
	}
}

// --- OSMHeader -------------------------------------------------------------

// diffDecodeHeader checks DecodeHeader against refDecodeHeader.
func diffDecodeHeader(t *testing.T, data []byte) {
	t.Helper()

	got, osmErr := osmbr.DecodeHeader(data)
	want, refErr := refDecodeHeader(data)
	if errAgree(t, "DecodeHeader", data, osmErr, refErr) {
		return
	}
	if osmErr != nil {
		return
	}
	eq(t, "DecodeHeader", "BBox.Left", data, got.BBox.Left, want.BBoxLeft)
	eq(t, "DecodeHeader", "BBox.Right", data, got.BBox.Right, want.BBoxRight)
	eq(t, "DecodeHeader", "BBox.Top", data, got.BBox.Top, want.BBoxTop)
	eq(t, "DecodeHeader", "BBox.Bottom", data, got.BBox.Bottom, want.BBoxBottom)
	eq(t, "DecodeHeader", "RequiredFeatures", data, got.RequiredFeatures, want.RequiredFeatures)
	eq(t, "DecodeHeader", "OptionalFeatures", data, got.OptionalFeatures, want.OptionalFeatures)
	eq(t, "DecodeHeader", "WritingProgram", data, got.WritingProgram, want.WritingProgram)
	eq(t, "DecodeHeader", "Source", data, got.Source, want.Source)
	eq(t, "DecodeHeader", "ReplicationTimestamp", data, got.ReplicationTimestamp, want.ReplicationTimestamp)
	eq(t, "DecodeHeader", "ReplicationSequenceNumber", data,
		got.ReplicationSequenceNumber, want.ReplicationSequenceNumber)
	eq(t, "DecodeHeader", "ReplicationBaseURL", data, got.ReplicationBaseURL, want.ReplicationBaseURL)
}

// --- PrimitiveBlock and groups ---------------------------------------------

// diffPrimitiveBlock checks PrimitiveBlock.DecodeFrom, its string table, and
// GroupScanner against the reference, then diffs every group's entities as
// reached through the scanner.
//
// The scanner path is what tests osmbr's split of the block into groups: the
// entities are decoded from the group bytes GroupScanner picked out and
// compared against the reference decoding the group bytes it picked out
// independently, so a split that differed anywhere would show up as differing
// entities.
func diffPrimitiveBlock(t *testing.T, data []byte) {
	t.Helper()

	var pb osmbr.PrimitiveBlock
	osmErr := pb.DecodeFrom(data)
	want, refErr := refDecodePrimitiveBlock(data)
	if errAgree(t, "PrimitiveBlock", data, osmErr, refErr) {
		return
	}
	if osmErr != nil {
		return
	}

	eq(t, "PrimitiveBlock", "Granularity", data, pb.Granularity, want.Granularity)
	eq(t, "PrimitiveBlock", "DateGranularity", data, pb.DateGranularity, want.DateGranularity)
	eq(t, "PrimitiveBlock", "LatOffset", data, pb.LatOffset, want.LatOffset)
	eq(t, "PrimitiveBlock", "LonOffset", data, pb.LonOffset, want.LonOffset)

	eq(t, "PrimitiveBlock", "NumStrings", data, pb.NumStrings(), len(want.Strings))
	for i := 0; i < pb.NumStrings() && i < len(want.Strings); i++ {
		if !bytes.Equal(pb.String(i), want.Strings[i]) {
			t.Errorf("PrimitiveBlock: String(%d) mismatch: %q vs %q\n  input: %s",
				i, pb.String(i), want.Strings[i], dumpBytes(data))
		}
	}

	// The groups are a second pass. DecodeFrom walks past the primitivegroup
	// field without reading it, so this pass can fail where that one did not.
	wantGroups, wantGroupErr := refGroups(data)

	i := 0
	gs := pb.Groups()
	for ; gs.Next(); i++ {
		if i >= len(wantGroups) {
			t.Errorf("PrimitiveBlock: Groups yielded more than the reference's %d groups\n  input: %s",
				len(wantGroups), dumpBytes(data))
			return
		}
		groupData := wantGroups[i].Data
		where := fmt.Sprintf("group[%d]", i)
		eq(t, "PrimitiveBlock", where+" type", data, int8(gs.Type()), wantGroups[i].Type)

		switch gs.Type() {
		case osmbr.GroupTypeDense:
			diffDense(t, where, groupData, func(buf *osmbr.DenseNodesBuf, info *osmbr.DenseInfoBuf) error {
				return gs.DecodeDenseNodes(buf, info)
			})
		case osmbr.GroupTypeNodes:
			diffNodesFrom(t, where, groupData, gs.NodeScanner())
		case osmbr.GroupTypeWays:
			diffWaysFrom(t, where, groupData, gs.WayScanner())
		case osmbr.GroupTypeRelations:
			diffRelationsFrom(t, where, groupData, gs.RelationScanner())
		}
	}
	if errAgree(t, "PrimitiveBlock.Groups", data, gs.Err(), wantGroupErr) {
		return
	}
	eq(t, "PrimitiveBlock", "group count", data, i, len(wantGroups))
}

// groupScannerOver wraps groupData as a one-group PrimitiveBlock and returns a
// scanner positioned on it. The entity scanners are reachable only through a
// GroupScanner, so a target that fuzzes group bytes has to build the wrapper.
//
// It reports ok=false when the group's leading tag is malformed, which is the
// one thing GroupScanner inspects before handing out a decoder.
func groupScannerOver(t *testing.T, groupData []byte) (osmbr.GroupScanner, bool) {
	t.Helper()
	block := pbLenDelim(2, groupData) // PrimitiveBlock.primitivegroup
	var pb osmbr.PrimitiveBlock
	if err := pb.DecodeFrom(block); err != nil {
		t.Fatalf("wrapping a group in a PrimitiveBlock must not fail: %v\n  group: %s",
			err, dumpBytes(groupData))
	}
	gs := pb.Groups()
	if !gs.Next() {
		return gs, false
	}
	return gs, true
}

// --- DenseNodes ------------------------------------------------------------

// denseSnapshot is a copy of everything DecodeDenseNodes writes.
type denseSnapshot struct {
	IDs, Lats, Lons        []int64
	KeysVals               []int32
	Versions               []int32
	Timestamps, Changesets []int64
	UIDs, UserSIDs         []int32
	Visibles               []bool
}

func snapshotDense(buf *osmbr.DenseNodesBuf, info *osmbr.DenseInfoBuf) denseSnapshot {
	s := denseSnapshot{
		IDs:      append([]int64(nil), buf.IDs...),
		Lats:     append([]int64(nil), buf.Lats...),
		Lons:     append([]int64(nil), buf.Lons...),
		KeysVals: append([]int32(nil), buf.KeysVals...),
	}
	if info != nil {
		s.Versions = append([]int32(nil), info.Versions...)
		s.Timestamps = append([]int64(nil), info.Timestamps...)
		s.Changesets = append([]int64(nil), info.Changesets...)
		s.UIDs = append([]int32(nil), info.UIDs...)
		s.UserSIDs = append([]int32(nil), info.UserSIDs...)
		s.Visibles = append([]bool(nil), info.Visibles...)
	}
	return s
}

// refDenseSnapshot converts a reference result into the same shape.
func refDenseSnapshot(dn refDenseNodes, withInfo bool) denseSnapshot {
	s := denseSnapshot{
		IDs:      append([]int64(nil), dn.IDs...),
		Lats:     append([]int64(nil), dn.Lats...),
		Lons:     append([]int64(nil), dn.Lons...),
		KeysVals: append([]int32(nil), dn.KeysVals...),
	}
	if withInfo {
		s.Versions = append([]int32(nil), dn.Info.Versions...)
		s.Timestamps = append([]int64(nil), dn.Info.Timestamps...)
		s.Changesets = append([]int64(nil), dn.Info.Changesets...)
		s.UIDs = append([]int32(nil), dn.Info.UIDs...)
		s.UserSIDs = append([]int32(nil), dn.Info.UserSIDs...)
		s.Visibles = append([]bool(nil), dn.Info.Visibles...)
	}
	return s
}

// diffDense checks a DenseNodes decode against the reference, both with and
// without a DenseInfoBuf, and checks that reusing the buffers does not carry
// values from one decode into the next.
//
// decode runs the decoder under test; the caller supplies it so that the same
// comparison serves both the standalone DecodeDenseNodes entry point and
// GroupScanner.DecodeDenseNodes.
func diffDense(t *testing.T, where string, groupData []byte,
	decode func(*osmbr.DenseNodesBuf, *osmbr.DenseInfoBuf) error) {
	t.Helper()

	for _, withInfo := range []bool{false, true} {
		what := where + " DecodeDenseNodes(info=nil)"
		if withInfo {
			what = where + " DecodeDenseNodes(info=set)"
		}

		var (
			buf  osmbr.DenseNodesBuf
			info osmbr.DenseInfoBuf
			ip   *osmbr.DenseInfoBuf
		)
		if withInfo {
			ip = &info
		}
		osmErr := decode(&buf, ip)
		refDN, refErr := refDecodeDenseNodes(groupData, withInfo)

		if errAgree(t, what, groupData, osmErr, refErr) {
			continue
		}
		if osmErr != nil {
			continue
		}
		got := snapshotDense(&buf, ip)
		eq(t, what, "result", groupData, got, refDenseSnapshot(refDN, withInfo))

		// Decoding into the same buffers again must give the same answer: the
		// buffers are reset by the decoder, not by the caller.
		if err := decode(&buf, ip); err != nil {
			t.Errorf("%s: reuse rejected a group it accepted: %v\n  input: %s",
				what, err, dumpBytes(groupData))
		} else {
			eq(t, what, "reuse", groupData, snapshotDense(&buf, ip), got)
		}
	}
}

// --- Node, Way, Relation ---------------------------------------------------

// The collect* functions run a scanner to exhaustion into the reference's own
// result types, so a scanner reached through GroupScanner and one reached
// through a synthetic wrapper are compared the same way.

func collectNodes(t *testing.T, ns osmbr.NodeScanner, groupData []byte) ([]refNode, error) {
	t.Helper()
	var (
		out  []refNode
		buf  osmbr.NodeBuf
		info osmbr.InfoBuf
	)
	for {
		id, lat, lon, ok := ns.Next(&buf, &info)
		if !ok {
			break
		}
		out = append(out, refNode{
			ID: id, Lat: lat, Lon: lon,
			Keys: append([]uint32(nil), buf.Keys...),
			Vals: append([]uint32(nil), buf.Vals...),
			Info: toRefInfo(info),
		})
		if len(out) > maxEntities {
			t.Fatalf("NodeScanner did not terminate on %d bytes", len(groupData))
		}
	}
	return out, ns.Err()
}

func collectWays(t *testing.T, ws osmbr.WayScanner, groupData []byte) ([]refWay, error) {
	t.Helper()
	var (
		out  []refWay
		buf  osmbr.WayBuf
		info osmbr.InfoBuf
	)
	for {
		id, ok := ws.Next(&buf, &info)
		if !ok {
			break
		}
		out = append(out, refWay{
			ID:   id,
			Keys: append([]uint32(nil), buf.Keys...),
			Vals: append([]uint32(nil), buf.Vals...),
			Refs: append([]int64(nil), buf.Refs...),
			Info: toRefInfo(info),
		})
		if len(out) > maxEntities {
			t.Fatalf("WayScanner did not terminate on %d bytes", len(groupData))
		}
	}
	return out, ws.Err()
}

func collectRelations(t *testing.T, rs osmbr.RelationScanner, groupData []byte) ([]refRelation, error) {
	t.Helper()
	var (
		out  []refRelation
		buf  osmbr.RelationBuf
		info osmbr.InfoBuf
	)
	for {
		id, ok := rs.Next(&buf, &info)
		if !ok {
			break
		}
		out = append(out, refRelation{
			ID:       id,
			Keys:     append([]uint32(nil), buf.Keys...),
			Vals:     append([]uint32(nil), buf.Vals...),
			RolesSID: append([]int32(nil), buf.RolesSID...),
			MemIDs:   append([]int64(nil), buf.MemIDs...),
			Types:    append([]int32(nil), buf.Types...),
			Info:     toRefInfo(info),
		})
		if len(out) > maxEntities {
			t.Fatalf("RelationScanner did not terminate on %d bytes", len(groupData))
		}
	}
	return out, rs.Err()
}

func diffNodesFrom(t *testing.T, where string, groupData []byte, ns osmbr.NodeScanner) {
	t.Helper()
	got, osmErr := collectNodes(t, ns, groupData)
	want, refErr := refDecodeNodes(groupData)
	diffEntities(t, where+" NodeScanner", groupData, osmErr, refErr, toAny(got), toAny(want))
}

func diffWaysFrom(t *testing.T, where string, groupData []byte, ws osmbr.WayScanner) {
	t.Helper()
	got, osmErr := collectWays(t, ws, groupData)
	want, refErr := refDecodeWays(groupData)
	diffEntities(t, where+" WayScanner", groupData, osmErr, refErr, toAny(got), toAny(want))
}

func diffRelationsFrom(t *testing.T, where string, groupData []byte, rs osmbr.RelationScanner) {
	t.Helper()
	got, osmErr := collectRelations(t, rs, groupData)
	want, refErr := refDecodeRelations(groupData)
	diffEntities(t, where+" RelationScanner", groupData, osmErr, refErr, toAny(got), toAny(want))
}

// diffEntities compares two entity runs. Each entity is framed independently
// and both sides walk the same field sequence, so the entities decoded before
// either side stops must match one for one; the counts must match too once both
// sides accept the whole group.
func diffEntities(t *testing.T, what string, input []byte, osmErr, refErr error, got, want []any) {
	t.Helper()
	for i := 0; i < len(got) && i < len(want); i++ {
		eq(t, what, fmt.Sprintf("entity[%d]", i), input, got[i], want[i])
	}
	if errAgree(t, what, input, osmErr, refErr) {
		return
	}
	eq(t, what, "entity count", input, len(got), len(want))
}

func toAny[T any](s []T) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func toRefInfo(i osmbr.InfoBuf) refInfo {
	return refInfo{
		Version:    i.Version,
		Timestamp:  i.Timestamp,
		Changeset:  i.Changeset,
		UID:        i.UID,
		UserSID:    i.UserSID,
		Visible:    i.Visible,
		HasVisible: i.HasVisible,
	}
}

// --- end-to-end ------------------------------------------------------------

// diffPBFFile runs the whole pipeline — framing, decompression, header and
// block decoding, every group, every entity — over one PBF byte stream,
// checking each stage against the reference.
func diffPBFFile(t *testing.T, data []byte) {
	t.Helper()

	diffBlockReader(t, data)

	// Walk the blocks the reference found. diffBlockReader has already checked
	// that osmbr found the same ones.
	blocks, _ := refBlocks(data)
	budget := inflateBudget
	for _, b := range blocks {
		if budget <= 0 {
			break
		}
		diffDecompress(t, b.Blob)
		payload, err := refDecompress(b.Blob)
		if err != nil {
			continue
		}
		budget -= len(payload)
		switch b.Type {
		case "OSMHeader":
			diffDecodeHeader(t, payload)
		case "OSMData":
			diffPrimitiveBlock(t, payload)
		}
	}

	diffPBFStream(t, data)
}

// diffPBFStream reads the file the way the package is meant to be used: one
// BlockReader recycling one buffer, feeding one Decompressor, with each block
// decoded before the next is read.
//
// Everything on this path is reused across blocks — the reader's blob buffer,
// the decompressor's output buffer and inflater, the block's string table — and
// each block's results are valid only until the next block is decompressed.
// Nothing else in the oracle spans blocks, so this is where a buffer handed out
// with the wrong lifetime would show up: a block that decodes correctly on its
// own but wrongly after the one before it.
func diffPBFStream(t *testing.T, data []byte) {
	t.Helper()

	want, _ := refBlocks(data)

	var (
		dec    osmbr.Decompressor
		pb     osmbr.PrimitiveBlock
		blob   []byte
		i      int
		ok     bool
		budget = inflateBudget
	)
	br := osmbr.NewBlockReader(bytes.NewReader(data))
	for blob, ok = br.NextInto(nil); ok; blob, ok = br.NextInto(blob[:0]) {
		if i >= len(want) {
			return // diffBlockReader has already reported the disagreement
		}
		if budget <= 0 {
			return
		}
		b := want[i]
		i++

		payload, osmErr := dec.Decompress(blob)
		budget -= len(payload)
		wantPayload, refErr := refDecompress(b.Blob)
		what := fmt.Sprintf("stream block[%d] Decompress", i-1)
		if errAgree(t, what, data, osmErr, refErr) {
			continue
		}
		if osmErr != nil {
			continue
		}
		if !bytes.Equal(payload, wantPayload) {
			t.Errorf("%s: reused Decompressor gave a different payload than a fresh one\n  input: %s",
				what, dumpBytes(data))
			continue
		}
		if b.Type != "OSMData" {
			continue
		}

		// The string table aliases payload, which the next Decompress
		// overwrites, so the block is read out in full here rather than later.
		if err := pb.DecodeFrom(payload); err != nil {
			continue
		}
		refPB, refErr := refDecodePrimitiveBlock(payload)
		if refErr != nil {
			continue
		}
		for j := 0; j < pb.NumStrings() && j < len(refPB.Strings); j++ {
			if !bytes.Equal(pb.String(j), refPB.Strings[j]) {
				t.Errorf("stream block[%d]: String(%d) = %q, want %q\n  input: %s",
					i-1, j, pb.String(j), refPB.Strings[j], dumpBytes(data))
				break
			}
		}
		refGrps, _ := refGroups(payload)
		gs := pb.Groups()
		for j := 0; gs.Next(); j++ {
			if j >= len(refGrps) {
				break
			}
			where := fmt.Sprintf("stream block[%d] group[%d]", i-1, j)
			g := refGrps[j].Data
			switch gs.Type() {
			case osmbr.GroupTypeDense:
				diffDense(t, where, g, func(buf *osmbr.DenseNodesBuf, info *osmbr.DenseInfoBuf) error {
					return gs.DecodeDenseNodes(buf, info)
				})
			case osmbr.GroupTypeNodes:
				diffNodesFrom(t, where, g, gs.NodeScanner())
			case osmbr.GroupTypeWays:
				diffWaysFrom(t, where, g, gs.WayScanner())
			case osmbr.GroupTypeRelations:
				diffRelationsFrom(t, where, g, gs.RelationScanner())
			}
		}
	}
}

// --- oracle self-checks ----------------------------------------------------

// TestRefScalars pins the reference's scalar conversions to protobuf's, for the
// values where a plausible implementation could differ. The expectations come
// from google.golang.org/protobuf: int32, int64, and uint32 truncate; sint64
// zigzag-decodes all 64 bits; sint32 masks to 32 bits and only then
// zigzag-decodes.
func TestRefScalars(t *testing.T) {
	t.Run("sint32", func(t *testing.T) {
		cases := []struct {
			v    uint64
			want int32
		}{
			{0, 0},
			{1, -1},
			{2, 1},
			{3, -2},
			{math.MaxUint32 - 1, math.MaxInt32}, // 0xfffffffe
			{math.MaxUint32, math.MinInt32},     // 0xffffffff
			// Bit 32 and above belong to no sint32 and are masked off. Decoding
			// all 64 bits first and truncating afterwards would put bit 32 on
			// the result's sign bit and give -2147483648 for the first of these.
			{1 << 32, 0},
			{1<<32 | 1, -1},
			{1<<32 | 2, 1},
			{1<<32 | math.MaxUint32, math.MinInt32},
			{math.MaxUint64, math.MinInt32},
		}
		for _, c := range cases {
			if got := refSint32(c.v); got != c.want {
				t.Errorf("refSint32(%#x) = %d, want %d", c.v, got, c.want)
			}
		}
	})

	t.Run("sint64", func(t *testing.T) {
		cases := []struct {
			v    uint64
			want int64
		}{
			{0, 0},
			{1, -1},
			{2, 1},
			{3, -2},
			{math.MaxUint64 - 1, math.MaxInt64},
			{math.MaxUint64, math.MinInt64},
		}
		for _, c := range cases {
			if got := refSint64(c.v); got != c.want {
				t.Errorf("refSint64(%#x) = %d, want %d", c.v, got, c.want)
			}
		}
	})

	t.Run("truncating", func(t *testing.T) {
		if got := refInt32(1<<32 | 7); got != 7 {
			t.Errorf("refInt32(1<<32|7) = %d, want 7", got)
		}
		if got := refInt32(math.MaxUint64); got != -1 {
			t.Errorf("refInt32(MaxUint64) = %d, want -1", got)
		}
		if got := refUint32(1<<32 | 7); got != 7 {
			t.Errorf("refUint32(1<<32|7) = %d, want 7", got)
		}
		if got := refInt64(math.MaxUint64); got != -1 {
			t.Errorf("refInt64(MaxUint64) = %d, want -1", got)
		}
		if !refBool(2) || !refBool(1) || refBool(0) {
			t.Error("refBool")
		}
	})
}

// TestRefVarintLimits pins the reference's varint length and overflow rules to
// protowire.ConsumeVarint's: at most ten bytes, with a tenth byte above 1
// overflowing uint64.
func TestRefVarintLimits(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    uint64
		wantErr bool
	}{
		{"single byte", []byte{0x01}, 1, false},
		{"two bytes", []byte{0x80, 0x01}, 128, false},
		{"max uint64", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}, math.MaxUint64, false},
		{"tenth byte 2 overflows", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02}, 0, true},
		{"eleven bytes", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, 0, true},
		{"truncated", []byte{0x80}, 0, true},
		{"empty", nil, 0, true},
		{"non-canonical zero", []byte{0x80, 0x00}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := refVarint(tt.in, 0)
			if (err != nil) != tt.wantErr {
				t.Fatalf("refVarint(%x) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("refVarint(%x) = %#x, want %#x", tt.in, got, tt.want)
			}
		})
	}
}

// TestDiffOracleOnRealFile runs the oracle over the bundled extract, so the
// reference is known to agree with osmbr on a real file and not only on the
// synthetic and mutated inputs the fuzz targets produce.
func TestDiffOracleOnRealFile(t *testing.T) {
	data := readTestFile(t)
	diffPBFFile(t, data)
}
