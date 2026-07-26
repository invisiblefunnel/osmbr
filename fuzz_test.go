package osmbr_test

// Native fuzz targets, one per decoder entry point, plus an end-to-end target
// over whole PBF byte streams.
//
// Every target is a differential test: it runs the decoder under test and the
// reference in reference_test.go over the same bytes and requires that they
// agree on whether the input is valid and on every value decoded from it. See
// differential_test.go for what agreement means. A target that only checked for
// panics would pass on a decoder that quietly returned the wrong numbers, which
// is the failure mode that matters most here.
//
// The seed corpora combine synthetic messages that reach specific branches with
// slices of the bundled extract, so the fuzzer starts from input that is already
// structurally valid and mutates outward from there. Inputs that once failed
// live in testdata/fuzz/<target>/ and are replayed by plain `go test`.

import (
	"os"
	"testing"

	"github.com/invisiblefunnel/osmbr"
)

// maxFuzzInput caps the input length every target will look at.
//
// The oracle's cost is roughly linear in input length — about half a microsecond
// per byte, across its several passes and both decoders — so a multi-megabyte
// input takes seconds. That is worse than slow: a fuzzing worker that spends
// seconds inside one input stops answering its coordinator, and the run ends
// with "context deadline exceeded" against the whole target instead of a finding.
//
// Little is given up. A decode bug is a property of a message's structure rather
// than its length, and the fuzzer agrees: across a full round no target kept an
// input longer than 3157 bytes as interesting, and this is twenty times that.
// Whole real files are checked exactly, and uncapped, by TestDiffOracleOnRealFile.
const maxFuzzInput = 1 << 16

// readTestFile returns the bundled extract's bytes, skipping the caller when it
// is unavailable.
func readTestFile(tb testing.TB) []byte {
	tb.Helper()
	data, err := os.ReadFile(testFile)
	if err != nil {
		tb.Skipf("testdata unavailable: %v", err)
	}
	return data
}

// seedCorpus holds seeds derived from the bundled extract.
//
// The extract's own bytes are too big to seed a fuzzer with — its first ways
// group alone is half a megabyte, and mutating inputs that large would cost
// more throughput than the realism is worth. So the entities are decoded and
// the first few of each kind re-encoded into a compact block that carries real
// IDs, coordinates, timestamps, and string indices at a size the fuzzer can
// work with. Full-file coverage is asserted separately and exactly, by
// TestDiffOracleOnRealFile.
type seedCorpus struct {
	file        []byte // a two-block PBF stream: OSMHeader then OSMData
	headerBlob  []byte // raw Blob of the OSMHeader block, as stored
	dataBlob    []byte // raw zlib Blob wrapping dataBlock
	headerBlock []byte // decompressed OSMHeader payload, as stored
	dataBlock   []byte // a compact PrimitiveBlock
	denseGroup  []byte // a compact dense group
	waysGroup   []byte // a compact ways group
	relsGroup   []byte // a compact relations group
	denseInfo   []byte // a real DenseInfo submessage covering one node
	info        []byte // a real Info submessage from the first way
}

// seedEntities bounds how many entities of each kind a compact seed carries.
const seedEntities = 8

// loadSeeds builds the compact seed corpus. Everything is left nil when the
// extract is unavailable, and callers skip nil seeds.
func loadSeeds(tb testing.TB) seedCorpus {
	tb.Helper()
	var s seedCorpus
	data, err := os.ReadFile(testFile)
	if err != nil {
		return s
	}

	blocks, err := refBlocks(data)
	if err != nil {
		tb.Fatalf("bundled extract does not parse: %v", err)
	}

	var strings [][]byte
	for _, b := range blocks {
		payload, err := refDecompress(b.Blob)
		if err != nil {
			tb.Fatalf("bundled extract block does not decompress: %v", err)
		}
		switch b.Type {
		case "OSMHeader":
			if s.headerBlob == nil {
				s.headerBlob = append([]byte(nil), b.Blob...)
				s.headerBlock = payload
			}
		case "OSMData":
			pb, err := refDecodePrimitiveBlock(payload)
			if err != nil {
				tb.Fatalf("bundled extract block does not decode: %v", err)
			}
			if strings == nil {
				strings = pb.Strings
				if len(strings) > 32 {
					strings = strings[:32]
				}
			}
			groups, err := refGroups(payload)
			if err != nil {
				tb.Fatalf("bundled extract block groups do not scan: %v", err)
			}
			for _, g := range groups {
				switch g.Type {
				case 2: // dense
					if s.denseGroup == nil {
						dn, err := refDecodeDenseNodes(g.Data, true)
						if err != nil {
							tb.Fatalf("bundled dense group does not decode: %v", err)
						}
						s.denseGroup, _ = compactDenseGroup(dn, seedEntities)
						// FuzzDenseInfo wraps its input around a single node, so
						// the arrays it seeds with have to be one entry long.
						_, s.denseInfo = compactDenseGroup(dn, 1)
					}
				case 3: // ways
					if s.waysGroup == nil {
						ways, err := refDecodeWays(g.Data)
						if err != nil {
							tb.Fatalf("bundled ways group does not decode: %v", err)
						}
						s.waysGroup = compactWaysGroup(ways, seedEntities)
						if len(ways) > 0 {
							s.info = encodeRefInfo(ways[0].Info)
						}
					}
				case 4: // relations
					if s.relsGroup == nil {
						rels, err := refDecodeRelations(g.Data)
						if err != nil {
							tb.Fatalf("bundled relations group does not decode: %v", err)
						}
						s.relsGroup = compactRelationsGroup(rels, seedEntities)
					}
				}
			}
		}
	}

	var st []byte
	for _, e := range strings {
		st = append(st, pbLenDelim(1, e)...)
	}
	s.dataBlock = concat(pbLenDelim(1, st), s.denseGroup, s.waysGroup, s.relsGroup,
		pbVarintField(17, 100), pbVarintField(18, 1000))
	s.dataBlob = zlibBlob(len(s.dataBlock), zlibCompress(tb, s.dataBlock))
	s.file = concat(
		pbfFrame("OSMHeader", s.headerBlob),
		pbfFrame("OSMData", s.dataBlob))
	return s
}

// deltas64 converts absolute values back to the deltas PBF stores, so decoded
// real values can be re-encoded.
func deltas64(vals []int64) []int64 {
	out := make([]int64, len(vals))
	var prev int64
	for i, v := range vals {
		out[i] = v - prev
		prev = v
	}
	return out
}

// deltas32 is deltas64 for the sint32 delta fields.
func deltas32(vals []int32) []int32 {
	out := make([]int32, len(vals))
	var prev int32
	for i, v := range vals {
		out[i] = v - prev
		prev = v
	}
	return out
}

// keysValsPrefix returns the flat keys_vals entries belonging to the first n
// nodes, delimiters included, or nil if the array does not cover them.
func keysValsPrefix(kv []int32, n int) []int32 {
	i := 0
	for range n {
		for i < len(kv) && kv[i] != 0 {
			if i+1 >= len(kv) {
				return nil
			}
			i += 2
		}
		if i >= len(kv) {
			return nil
		}
		i++ // the 0 delimiter
	}
	return kv[:i]
}

// compactDenseGroup re-encodes the first n nodes of a decoded dense group,
// returning the group bytes and the DenseInfo submessage inside them.
func compactDenseGroup(dn refDenseNodes, n int) (group, denseInfo []byte) {
	n = min(n, len(dn.IDs))
	if n == 0 {
		return nil, nil
	}
	fields := concat(
		pbPackedSint64(1, deltas64(dn.IDs[:n])),
		pbPackedSint64(8, deltas64(dn.Lats[:n])),
		pbPackedSint64(9, deltas64(dn.Lons[:n])))
	if kv := keysValsPrefix(dn.KeysVals, n); kv != nil {
		fields = concat(fields, pbPackedInt32(10, kv))
	}
	// Each DenseInfo array is carried only if it covers all n nodes, since a
	// short one would make the seed invalid.
	if len(dn.Info.Versions) >= n {
		denseInfo = concat(denseInfo, pbPackedInt32(1, dn.Info.Versions[:n]))
	}
	if len(dn.Info.Timestamps) >= n {
		denseInfo = concat(denseInfo, pbPackedSint64(2, deltas64(dn.Info.Timestamps[:n])))
	}
	if len(dn.Info.Changesets) >= n {
		denseInfo = concat(denseInfo, pbPackedSint64(3, deltas64(dn.Info.Changesets[:n])))
	}
	if len(dn.Info.UIDs) >= n {
		denseInfo = concat(denseInfo, pbPackedSint32(4, deltas32(dn.Info.UIDs[:n])))
	}
	if len(dn.Info.UserSIDs) >= n {
		denseInfo = concat(denseInfo, pbPackedSint32(5, deltas32(dn.Info.UserSIDs[:n])))
	}
	if len(dn.Info.Visibles) >= n {
		denseInfo = concat(denseInfo, pbPackedBool(6, dn.Info.Visibles[:n]))
	}
	if denseInfo != nil {
		fields = concat(fields, pbLenDelim(5, denseInfo))
	}
	return pbLenDelim(2, fields), denseInfo
}

// compactWaysGroup re-encodes the first n ways of a decoded ways group.
func compactWaysGroup(ways []refWay, n int) []byte {
	var out []byte
	for _, w := range ways[:min(n, len(ways))] {
		way := pbVarintField(1, uint64(w.ID))
		if len(w.Keys) > 0 {
			way = concat(way, pbPackedUint32(2, w.Keys), pbPackedUint32(3, w.Vals))
		}
		if len(w.Refs) > 0 {
			way = concat(way, pbPackedSint64(8, deltas64(w.Refs)))
		}
		way = concat(way, pbLenDelim(4, encodeRefInfo(w.Info)))
		out = concat(out, pbLenDelim(3, way))
	}
	return out
}

// compactRelationsGroup re-encodes the first n relations of a decoded group.
// Member lists are truncated as well: a real multipolygon can carry thousands of
// members, which would make this the largest seed by an order of magnitude.
func compactRelationsGroup(rels []refRelation, n int) []byte {
	const maxMembers = 8
	var out []byte
	for _, r := range rels[:min(n, len(rels))] {
		rel := pbVarintField(1, uint64(r.ID))
		if len(r.Keys) > 0 {
			rel = concat(rel, pbPackedUint32(2, r.Keys), pbPackedUint32(3, r.Vals))
		}
		// The three member arrays are parallel, so they are cut to one length.
		if m := min(maxMembers, len(r.MemIDs), len(r.RolesSID), len(r.Types)); m > 0 {
			rel = concat(rel,
				pbPackedInt32(8, r.RolesSID[:m]),
				pbPackedSint64(9, deltas64(r.MemIDs[:m])),
				pbPackedInt32(10, r.Types[:m]))
		}
		rel = concat(rel, pbLenDelim(4, encodeRefInfo(r.Info)))
		out = concat(out, pbLenDelim(4, rel))
	}
	return out
}

// encodeRefInfo re-encodes a decoded Info message.
func encodeRefInfo(info refInfo) []byte {
	out := concat(
		pbVarintField(1, uint64(info.Version)),
		pbVarintField(2, uint64(info.Timestamp)),
		pbVarintField(3, uint64(info.Changeset)),
		pbVarintField(4, uint64(info.UID)),
		pbVarintField(5, uint64(info.UserSID)))
	if info.HasVisible {
		v := uint64(0)
		if info.Visible {
			v = 1
		}
		out = concat(out, pbVarintField(6, v))
	}
	return out
}

// addSeeds adds every non-empty seed to the corpus.
func addSeeds(f *testing.F, seeds ...[]byte) {
	for _, s := range seeds {
		if len(s) > 0 {
			f.Add(s)
		}
	}
}

// --- framing ---------------------------------------------------------------

// FuzzBlockReader fuzzes the FileBlock framing: the big-endian length prefix,
// the BlobHeader, and the Blob that follows.
func FuzzBlockReader(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0, 0, 0, 1, 0})
	f.Add(pbfFrame("OSMData", pbLenDelim(1, []byte("payload"))))
	f.Add(pbfFrame("OSMHeader", pbLenDelim(1, []byte("hdr"))))
	// Two frames back to back, so a mutation can damage the second only.
	f.Add(append(pbfFrame("OSMHeader", pbLenDelim(1, []byte("hdr"))),
		pbfFrame("OSMData", pbLenDelim(1, []byte("payload")))...))
	// A BlobHeader with no type and a datasize the Blob does not satisfy.
	f.Add(append([]byte{0, 0, 0, 3}, append(pbVarintField(3, 99), 0x00)...))

	seeds := loadSeeds(f)
	addSeeds(f, seeds.file)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzInput {
			return
		}
		diffBlockReader(t, data)
	})
}

// --- decompression ---------------------------------------------------------

// FuzzDecompressor fuzzes Blob parsing and zlib inflation, including the zlib
// header checks, the raw_size length pin, and the Adler-32 trailer.
func FuzzDecompressor(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(pbLenDelim(1, []byte("raw payload"))) // raw
	f.Add(pbLenDelim(1, nil))                   // raw, empty
	f.Add(pbLenDelim(4, []byte("lzma")))        // unsupported compression
	f.Add(pbLenDelim(7, []byte("zstd")))        // unsupported compression
	f.Add(pbVarintField(2, 10))                 // raw_size with no payload
	f.Add(pbLenDelim(3, []byte{0x78, 0x9c}))    // zlib header only
	f.Add(append(pbVarintField(2, 3), pbLenDelim(3, zlibCompress(f, []byte("abc")))...))
	f.Add(pbLenDelim(3, zlibCompress(f, []byte("abc")))) // zlib, no raw_size
	f.Add(zlibBlob(11, zlibCompress(f, []byte("raw payload"))))

	seeds := loadSeeds(f)
	addSeeds(f, seeds.dataBlob, seeds.headerBlob)

	f.Fuzz(func(t *testing.T, blob []byte) {
		if len(blob) > maxFuzzInput {
			return
		}
		diffDecompress(t, blob)
	})
}

// --- OSMHeader -------------------------------------------------------------

// FuzzDecodeHeader fuzzes the decompressed OSMHeader payload.
func FuzzDecodeHeader(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(pbLenDelim(4, []byte("OsmSchema-V0.6")))
	f.Add(pbLenDelim(5, []byte("Sort.Type_then_ID")))
	f.Add(pbLenDelim(16, []byte("osmium/1.16.0")))
	f.Add(pbLenDelim(1, // bbox
		concat(pbSint64Field(1, -64000000000), pbSint64Field(2, -64000000000),
			pbSint64Field(3, 18000000000), pbSint64Field(4, 17000000000))))
	f.Add(concat(pbVarintField(32, 1700000000), pbVarintField(33, 42),
		pbLenDelim(34, []byte("https://example.org/"))))
	seeds := loadSeeds(f)
	addSeeds(f, seeds.headerBlock)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzInput {
			return
		}
		diffDecodeHeader(t, data)
	})
}

// --- PrimitiveBlock --------------------------------------------------------

// FuzzPrimitiveBlock fuzzes a whole decompressed OSMData payload: the string
// table, the granularity and offset fields, the split into PrimitiveGroups, and
// every entity in every group.
func FuzzPrimitiveBlock(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(pbLenDelim(1, pbLenDelim(1, []byte("highway"))))
	f.Add(concat(
		pbLenDelim(1, concat(pbLenDelim(1, nil), pbLenDelim(1, []byte("highway")))),
		pbVarintField(17, 100), pbVarintField(18, 1000),
		pbVarintField(19, 0), pbVarintField(20, 0)))
	// One group of each kind, so the fuzzer can mutate the group tag itself.
	f.Add(pbLenDelim(2, pbLenDelim(2, pbPackedSint64(1, []int64{1, 1, 1}))))
	f.Add(pbLenDelim(2, pbLenDelim(1, pbSint64Field(1, 7))))
	f.Add(pbLenDelim(2, pbLenDelim(3, pbVarintField(1, 7))))
	f.Add(pbLenDelim(2, pbLenDelim(4, pbVarintField(1, 7))))
	f.Add(pbLenDelim(2, pbLenDelim(5, pbVarintField(1, 7))))

	seeds := loadSeeds(f)
	addSeeds(f, seeds.dataBlock)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzInput {
			return
		}
		diffPrimitiveBlock(t, data)
	})
}

// --- PrimitiveGroup entry points -------------------------------------------
//
// The four decoders below all take PrimitiveGroup bytes. The fuzzer mutates
// those bytes directly and each target supplies its own wrapper, so a mutation
// lands inside the group rather than on the framing around it.

// FuzzDecodeDenseNodes fuzzes DenseNodes decoding, including DenseInfo and the
// parallel-array length checks.
func FuzzDecodeDenseNodes(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(pbLenDelim(2, nil))
	f.Add(pbLenDelim(2, pbPackedSint64(1, []int64{1, 1, 1})))
	// A complete three-node group: ids, lats, lons, tags, and metadata.
	f.Add(pbLenDelim(2, concat(
		pbPackedSint64(1, []int64{100, 1, 1}),
		pbPackedSint64(8, []int64{500000000, 10, 10}),
		pbPackedSint64(9, []int64{-600000000, -10, -10}),
		pbPackedInt32(10, []int32{1, 2, 0, 0, 3, 4, 0}),
		pbLenDelim(5, concat(
			pbPackedInt32(1, []int32{1, 1, 1}),
			pbPackedSint64(2, []int64{1700000000000, 1000, 1000}),
			pbPackedSint64(3, []int64{50, 1, 1}),
			pbPackedSint32(4, []int32{7, 0, 0}),
			pbPackedSint32(5, []int32{1, 0, 0}),
			pbPackedBool(6, []bool{true, true, true}))))))
	// Lengths that do not line up, which must be rejected.
	f.Add(pbLenDelim(2, concat(
		pbPackedSint64(1, []int64{1, 1}), pbPackedSint64(8, []int64{1}),
		pbPackedSint64(9, []int64{1}))))
	// DenseInfo arrays shorter than the node arrays.
	f.Add(pbLenDelim(2, concat(
		pbPackedSint64(1, []int64{1, 1}), pbPackedSint64(8, []int64{1, 1}),
		pbPackedSint64(9, []int64{1, 1}),
		pbLenDelim(5, pbPackedSint32(5, []int32{1})))))
	// The unpacked encoding of packed fields, and a field split in two entries.
	f.Add(pbLenDelim(2, concat(
		pbSint64Field(1, 5), pbSint64Field(1, 5),
		pbSint64Field(8, 1), pbSint64Field(8, 1),
		pbPackedSint64(9, []int64{1}), pbPackedSint64(9, []int64{1}))))
	// A sint32 delta carrying bit 32, where masking and truncating differ.
	f.Add(pbLenDelim(2, concat(
		pbPackedSint64(1, []int64{1}), pbPackedSint64(8, []int64{1}),
		pbPackedSint64(9, []int64{1}),
		pbLenDelim(5, pbLenDelim(5, []byte{0x80, 0x80, 0x80, 0x80, 0x10})))))
	seeds := loadSeeds(f)
	addSeeds(f, seeds.denseGroup)

	f.Fuzz(func(t *testing.T, groupData []byte) {
		if len(groupData) > maxFuzzInput {
			return
		}
		// The standalone entry point takes group bytes directly.
		diffDense(t, "direct", groupData, func(buf *osmbr.DenseNodesBuf, info *osmbr.DenseInfoBuf) error {
			return osmbr.DecodeDenseNodes(groupData, buf, info)
		})
		// The same group reached through a GroupScanner, which is how a caller
		// walking a real block gets to it.
		if gs, ok := groupScannerOver(t, groupData); ok && gs.Type() == osmbr.GroupTypeDense {
			diffDense(t, "scanner", groupData, func(buf *osmbr.DenseNodesBuf, info *osmbr.DenseInfoBuf) error {
				return gs.DecodeDenseNodes(buf, info)
			})
		}
	})
}

// FuzzNodeScanner fuzzes the non-dense Node decoder.
func FuzzNodeScanner(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(pbLenDelim(1, nil))
	f.Add(pbLenDelim(1, concat(pbSint64Field(1, 7), pbSint64Field(8, 5), pbSint64Field(9, -5))))
	f.Add(concat(
		pbLenDelim(1, concat(pbSint64Field(1, 1), pbSint64Field(8, 1), pbSint64Field(9, 1),
			pbPackedUint32(2, []uint32{1, 2}), pbPackedUint32(3, []uint32{3, 4}),
			pbLenDelim(4, concat(pbVarintField(1, 3), pbVarintField(2, 1700), pbVarintField(3, 9),
				pbVarintField(4, 42), pbVarintField(5, 1), pbVarintField(6, 1))))),
		pbLenDelim(1, pbSint64Field(1, 2))))
	// Two info submessages, where merge and replace semantics differ.
	f.Add(pbLenDelim(1, concat(
		pbLenDelim(4, pbVarintField(1, 3)), pbLenDelim(4, pbVarintField(4, 9)))))

	f.Fuzz(func(t *testing.T, groupData []byte) {
		if len(groupData) > maxFuzzInput {
			return
		}
		gs, ok := groupScannerOver(t, groupData)
		if !ok {
			return
		}
		diffNodesFrom(t, "fuzz", groupData, gs.NodeScanner())
		// The nil-info path skips Info decoding entirely rather than zeroing
		// and filling a buffer; it must not crash or hang either.
		exhaustNodes(t, gs.NodeScanner())
	})
}

// FuzzWayScanner fuzzes the Way decoder, whose refs are delta-coded.
func FuzzWayScanner(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(pbLenDelim(3, nil))
	f.Add(pbLenDelim(3, concat(pbVarintField(1, 7), pbPackedSint64(8, []int64{100, 1, 1, -2}))))
	f.Add(concat(
		pbLenDelim(3, concat(pbVarintField(1, 1),
			pbPackedUint32(2, []uint32{1, 2}), pbPackedUint32(3, []uint32{3, 4}),
			pbPackedSint64(8, []int64{10, 1, 1}),
			pbLenDelim(4, concat(pbVarintField(1, 3), pbVarintField(5, 12), pbVarintField(6, 0))))),
		pbLenDelim(3, pbVarintField(1, 2))))
	// refs split across a packed and an unpacked entry, so the running delta
	// has to carry from one to the other.
	f.Add(pbLenDelim(3, concat(pbPackedSint64(8, []int64{10, 1}), pbSint64Field(8, 1))))
	// A ten-byte refs delta, the longest a varint can be.
	f.Add(pbLenDelim(3, pbLenDelim(8,
		[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01})))

	seeds := loadSeeds(f)
	addSeeds(f, seeds.waysGroup)

	f.Fuzz(func(t *testing.T, groupData []byte) {
		if len(groupData) > maxFuzzInput {
			return
		}
		gs, ok := groupScannerOver(t, groupData)
		if !ok {
			return
		}
		diffWaysFrom(t, "fuzz", groupData, gs.WayScanner())
		exhaustWays(t, gs.WayScanner())
	})
}

// FuzzRelationScanner fuzzes the Relation decoder, whose memids are delta-coded.
func FuzzRelationScanner(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(pbLenDelim(4, nil))
	f.Add(pbLenDelim(4, concat(pbVarintField(1, 7),
		pbPackedInt32(8, []int32{1, 2}), pbPackedSint64(9, []int64{100, 1}),
		pbPackedInt32(10, []int32{0, 1}))))
	f.Add(concat(
		pbLenDelim(4, concat(pbVarintField(1, 1),
			pbPackedUint32(2, []uint32{1}), pbPackedUint32(3, []uint32{2}),
			pbPackedInt32(8, []int32{1, 2, 3}),
			pbPackedSint64(9, []int64{10, 1, 1}),
			pbPackedInt32(10, []int32{0, 1, 2}),
			pbLenDelim(4, pbVarintField(1, 3)))),
		pbLenDelim(4, pbVarintField(1, 2))))
	// Negative int32 members, which encode as ten-byte varints.
	f.Add(pbLenDelim(4, concat(pbPackedInt32(8, []int32{-1}), pbPackedInt32(10, []int32{-1}))))

	seeds := loadSeeds(f)
	addSeeds(f, seeds.relsGroup)

	f.Fuzz(func(t *testing.T, groupData []byte) {
		if len(groupData) > maxFuzzInput {
			return
		}
		gs, ok := groupScannerOver(t, groupData)
		if !ok {
			return
		}
		diffRelationsFrom(t, "fuzz", groupData, gs.RelationScanner())
		exhaustRelations(t, gs.RelationScanner())
	})
}

// FuzzGroupScanner fuzzes the split of a PrimitiveBlock into PrimitiveGroups
// and the classification of each one, driving the scanner through every decoder
// it hands out regardless of the type it reported.
func FuzzGroupScanner(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(pbLenDelim(2, nil))
	f.Add(concat(pbLenDelim(2, pbLenDelim(1, nil)), pbLenDelim(2, pbLenDelim(3, nil))))
	// A group whose first field has a valid tag but an unusable wire type: the
	// type peek reads the tag only, so this classifies rather than failing.
	f.Add(pbLenDelim(2, pbTag(2, 3)))
	// A group led by a field no group type claims.
	f.Add(pbLenDelim(2, pbVarintField(9, 1)))
	// Groups interleaved with other PrimitiveBlock fields.
	f.Add(concat(pbLenDelim(1, pbLenDelim(1, nil)), pbLenDelim(2, pbLenDelim(3, nil)),
		pbVarintField(17, 100), pbLenDelim(2, pbLenDelim(4, nil))))

	seeds := loadSeeds(f)
	addSeeds(f, seeds.dataBlock)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzInput {
			return
		}
		var pb osmbr.PrimitiveBlock
		if err := pb.DecodeFrom(data); err != nil {
			return
		}
		// Every decoder must survive being pointed at a group of the wrong
		// kind: Type is a hint from the group's first field, not a guarantee,
		// and a caller may ignore it.
		gs := pb.Groups()
		for i := 0; gs.Next(); i++ {
			if i > maxEntities {
				t.Fatalf("Groups did not terminate on %d bytes", len(data))
			}
			_ = gs.Type()
			var (
				buf  osmbr.DenseNodesBuf
				info osmbr.DenseInfoBuf
			)
			_ = gs.DecodeDenseNodes(&buf, &info)
			exhaustNodes(t, gs.NodeScanner())
			exhaustWays(t, gs.WayScanner())
			exhaustRelations(t, gs.RelationScanner())
		}
		_ = gs.Err()

		// The same block must split the same way every time it is walked.
		diffPrimitiveBlock(t, data)
	})
}

// --- Info ------------------------------------------------------------------

// FuzzInfo fuzzes the per-entity Info decoder by carrying the fuzzer's bytes as
// a Way's info field, which is the shortest path to it from the public API.
func FuzzInfo(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(pbVarintField(1, 3))
	f.Add(concat(pbVarintField(1, 3), pbVarintField(2, 1700000000000),
		pbVarintField(3, 99), pbVarintField(4, 42), pbVarintField(5, 7),
		pbVarintField(6, 1)))
	f.Add(pbVarintField(6, 0))                              // visible=false, present
	f.Add(pbVarintField(5, 1<<32|7))                        // user_sid past 32 bits
	f.Add(pbVarintField(4, ^uint64(0)))                     // uid -1, a ten-byte varint
	f.Add(concat(pbVarintField(1, 1), pbVarintField(1, 2))) // repeated, last wins

	seeds := loadSeeds(f)
	addSeeds(f, seeds.info)

	f.Fuzz(func(t *testing.T, infoData []byte) {
		if len(infoData) > maxFuzzInput {
			return
		}
		groupData := pbLenDelim(3, pbLenDelim(4, infoData)) // ways[0].info
		gs, ok := groupScannerOver(t, groupData)
		if !ok {
			return
		}
		diffWaysFrom(t, "info", groupData, gs.WayScanner())
	})
}

// FuzzDenseInfo fuzzes the DenseInfo decoder by carrying the fuzzer's bytes as
// a DenseNodes denseinfo field, alongside one node so the length checks apply.
func FuzzDenseInfo(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(pbPackedInt32(1, []int32{1}))
	f.Add(pbPackedSint64(2, []int64{1700000000000}))
	f.Add(pbPackedSint32(4, []int32{7}))
	f.Add(pbPackedSint32(5, []int32{1}))
	f.Add(pbPackedBool(6, []bool{true}))
	f.Add(concat(pbPackedInt32(1, []int32{1}), pbPackedSint64(2, []int64{1}),
		pbPackedSint64(3, []int64{1}), pbPackedSint32(4, []int32{1}),
		pbPackedSint32(5, []int32{1}), pbPackedBool(6, []bool{true})))
	// uid and user_sid deltas carrying bit 32, where masking and truncating
	// after a 64-bit zigzag decode disagree.
	f.Add(pbLenDelim(4, []byte{0x80, 0x80, 0x80, 0x80, 0x10}))
	f.Add(pbLenDelim(5, []byte{0x80, 0x80, 0x80, 0x80, 0x10}))
	// A user_sid split across two entries, so the delta has to carry over.
	f.Add(concat(pbPackedSint32(5, []int32{3}), pbPackedSint32(5, []int32{4})))

	seeds := loadSeeds(f)
	addSeeds(f, seeds.denseInfo)

	f.Fuzz(func(t *testing.T, infoData []byte) {
		if len(infoData) > maxFuzzInput {
			return
		}
		// One node, so a DenseInfo array of length one is the valid length.
		groupData := pbLenDelim(2, concat(
			pbPackedSint64(1, []int64{1}),
			pbPackedSint64(8, []int64{1}),
			pbPackedSint64(9, []int64{1}),
			pbLenDelim(5, infoData)))
		diffDense(t, "denseinfo", groupData, func(buf *osmbr.DenseNodesBuf, info *osmbr.DenseInfoBuf) error {
			return osmbr.DecodeDenseNodes(groupData, buf, info)
		})
	})
}

// --- end to end ------------------------------------------------------------

// FuzzPBFFile fuzzes whole PBF byte streams through the entire pipeline:
// framing, decompression, and then every block, group, and entity. It is the
// only target where a mutation can reach one stage by way of another, which is
// where a lifetime or buffer-reuse mistake would show up.
func FuzzPBFFile(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(pbfFrame("OSMData", pbLenDelim(1, []byte("payload"))))
	// A header block and a data block, both uncompressed, that decode cleanly.
	header := pbLenDelim(4, []byte("OsmSchema-V0.6"))
	block := concat(
		pbLenDelim(1, concat(pbLenDelim(1, nil), pbLenDelim(1, []byte("highway")))),
		pbLenDelim(2, pbLenDelim(2, concat(
			pbPackedSint64(1, []int64{1, 1}),
			pbPackedSint64(8, []int64{1, 1}),
			pbPackedSint64(9, []int64{1, 1})))))
	f.Add(concat(
		pbfFrame("OSMHeader", pbLenDelim(1, header)),
		pbfFrame("OSMData", pbLenDelim(1, block))))
	// The same pair, zlib compressed, so the inflater is on the path.
	f.Add(concat(
		pbfFrame("OSMHeader", zlibBlob(len(header), zlibCompress(f, header))),
		pbfFrame("OSMData", zlibBlob(len(block), zlibCompress(f, block)))))

	seeds := loadSeeds(f)
	addSeeds(f, seeds.file)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzInput {
			return
		}
		diffPBFFile(t, data)
	})
}

// --- helpers ---------------------------------------------------------------

// concat joins wire-format fragments.
func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// The exhaust* helpers drive a scanner to the end with no InfoBuf, which is the
// code path that skips Info rather than decoding it. They assert nothing beyond
// termination; the differential comparison happens with an InfoBuf attached.

func exhaustNodes(t *testing.T, ns osmbr.NodeScanner) {
	t.Helper()
	var buf osmbr.NodeBuf
	for i := 0; ; i++ {
		if _, _, _, ok := ns.Next(&buf, nil); !ok {
			break
		}
		if i > maxEntities {
			t.Fatal("NodeScanner did not terminate")
		}
	}
	_ = ns.Err()
}

func exhaustWays(t *testing.T, ws osmbr.WayScanner) {
	t.Helper()
	var buf osmbr.WayBuf
	for i := 0; ; i++ {
		if _, ok := ws.Next(&buf, nil); !ok {
			break
		}
		if i > maxEntities {
			t.Fatal("WayScanner did not terminate")
		}
	}
	_ = ws.Err()
}

func exhaustRelations(t *testing.T, rs osmbr.RelationScanner) {
	t.Helper()
	var buf osmbr.RelationBuf
	for i := 0; ; i++ {
		if _, ok := rs.Next(&buf, nil); !ok {
			break
		}
		if i > maxEntities {
			t.Fatal("RelationScanner did not terminate")
		}
	}
	_ = rs.Err()
}
