package osmbr_test

import (
	"bytes"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/invisiblefunnel/osmbr"
)

// Benchmark suite for osmbr. Two tiers:
//
//	Tier A — micro-benchmarks against synthetic inputs, isolating each hot
//	         path so regressions can be localized.
//	Tier B — end-to-end benchmarks against the bundled testdata PBF,
//	         reflecting realistic block-size and entity-mix distributions.
//
// Run: go test -bench=. -benchmem -run=^$ ./...
// Compare runs: save the output of two runs and use benchstat.

// --- Shared fixtures ---

// testPBFSets caches bytes derived from the testdata PBF file so each
// benchmark can preload its inputs outside the timer.
type testPBFSets struct {
	file        []byte   // raw file bytes
	dataBlobs   [][]byte // raw Blob protobuf bytes from OSMData blocks
	dataBlocks  [][]byte // decompressed PrimitiveBlock bytes from OSMData
	headerBlock []byte   // decompressed OSMHeader bytes (for BenchmarkDecodeHeader)
}

var (
	pbfSetsOnce sync.Once
	pbfSets     *testPBFSets
)

func loadTestPBFSets(tb testing.TB) *testPBFSets {
	tb.Helper()
	pbfSetsOnce.Do(func() {
		file, err := os.ReadFile(testFile)
		if err != nil {
			tb.Fatalf("read %s: %v", testFile, err)
		}
		s := &testPBFSets{file: file}
		br := osmbr.NewBlockReader(bytes.NewReader(file))
		var dec osmbr.Decompressor
		for br.Next() {
			blob := append([]byte(nil), br.Blob()...)
			data, err := dec.Decompress(br.Blob())
			if err != nil {
				tb.Fatalf("setup Decompress: %v", err)
			}
			body := append([]byte(nil), data...)
			if br.Type() == "OSMHeader" {
				s.headerBlock = body
				continue
			}
			s.dataBlobs = append(s.dataBlobs, blob)
			s.dataBlocks = append(s.dataBlocks, body)
		}
		if err := br.Err(); err != nil {
			tb.Fatalf("setup BlockReader: %v", err)
		}
		pbfSets = s
	})
	return pbfSets
}

// buildDenseNodesGroup returns a PrimitiveGroup body containing one
// DenseNodes submessage with n nodes. All deltas are small so varints
// stay 1 byte, giving a stable per-node throughput measurement.
func buildDenseNodesGroup(n int, withInfo bool) []byte {
	ids := make([]int64, n)
	lats := make([]int64, n)
	lons := make([]int64, n)
	for i := range ids {
		ids[i] = 1
		lats[i] = 1
		lons[i] = 1
	}
	var info []byte
	if withInfo {
		versions := make([]int32, n)
		timestamps := make([]int64, n)
		changesets := make([]int64, n)
		uids := make([]int32, n)
		userSIDs := make([]uint32, n)
		for i := 0; i < n; i++ {
			versions[i] = 1
			timestamps[i] = 1
			changesets[i] = 1
			uids[i] = 1
			userSIDs[i] = 1
		}
		info = pbPackedInt32(1, versions)
		info = append(info, pbPackedSint64(2, timestamps)...)
		info = append(info, pbPackedSint64(3, changesets)...)
		info = append(info, pbPackedSint32(4, uids)...)
		info = append(info, pbPackedUint32(5, userSIDs)...)
	}
	return denseGroupBytes(ids, lats, lons, nil, info)
}

// infoSubmessage returns a synthetic Info submessage body.
func infoSubmessage() []byte {
	b := pbVarintField(1, 1)                       // version
	b = append(b, pbVarintField(2, 1700000000)...) // timestamp
	b = append(b, pbVarintField(3, 1)...)          // changeset
	b = append(b, pbVarintField(4, 1)...)          // uid
	b = append(b, pbVarintField(5, 0)...)          // user_sid
	b = append(b, pbVarintField(6, 1)...)          // visible
	return b
}

// buildWaysGroupN returns a PrimitiveGroup body with nWays Way messages,
// each with nTags tags and nRefs refs. If withInfo, each Way also carries
// an Info submessage.
func buildWaysGroupN(nWays, nTags, nRefs int, withInfo bool) []byte {
	keys := make([]uint32, nTags)
	vals := make([]uint32, nTags)
	for i := 0; i < nTags; i++ {
		keys[i] = uint32(i + 1)
		vals[i] = uint32(i + 2)
	}
	refs := make([]int64, nRefs)
	for i := 0; i < nRefs; i++ {
		refs[i] = 1
	}
	var info []byte
	if withInfo {
		info = infoSubmessage()
	}
	ways := make([][]byte, nWays)
	for i := 0; i < nWays; i++ {
		w := pbVarintField(1, uint64(i+1))
		if nTags > 0 {
			w = append(w, pbPackedUint32(2, keys)...)
			w = append(w, pbPackedUint32(3, vals)...)
		}
		if info != nil {
			w = append(w, pbLenDelim(4, info)...)
		}
		if nRefs > 0 {
			w = append(w, pbPackedSint64(8, refs)...)
		}
		ways[i] = w
	}
	return waysGroup(ways...)
}

// buildRelationsGroupN returns a PrimitiveGroup body with nRel Relation
// messages, each with nMembers members (with alternating types) and 3 tags.
func buildRelationsGroupN(nRel, nMembers int) []byte {
	keys := []uint32{1, 2, 3}
	vals := []uint32{4, 5, 6}
	rolesSID := make([]int32, nMembers)
	memIDs := make([]int64, nMembers)
	types := make([]int32, nMembers)
	for i := 0; i < nMembers; i++ {
		rolesSID[i] = int32(i%4 + 1)
		memIDs[i] = 1
		types[i] = int32(i % 3)
	}
	rels := make([][]byte, nRel)
	for i := 0; i < nRel; i++ {
		rels[i] = relationBytes(int64(i+1), keys, vals, rolesSID, memIDs, types)
	}
	return relationsGroup(rels...)
}

// buildNodesGroup returns a PrimitiveGroup body containing nNodes non-dense
// Node submessages.
func buildNodesGroup(nNodes int) []byte {
	var group []byte
	for i := 0; i < nNodes; i++ {
		node := pbSint64Field(1, int64(i+1)) // id
		node = append(node, pbSint64Field(8, 1)...)
		node = append(node, pbSint64Field(9, 1)...)
		group = append(group, pbLenDelim(1, node)...)
	}
	return group
}

// buildSyntheticFrames returns a BlockReader input containing nFrames
// OSMData frames, each with a small raw-blob payload. Used by
// BenchmarkBlockReaderNext to measure framing cost without disk I/O.
func buildSyntheticFrames(nFrames, blobBytes int) []byte {
	blob := pbLenDelim(1, bytes.Repeat([]byte{0xAB}, blobBytes))
	frame := pbfFrame("OSMData", blob)
	out := make([]byte, 0, len(frame)*nFrames)
	for i := 0; i < nFrames; i++ {
		out = append(out, frame...)
	}
	return out
}

// buildStringTable returns n deterministic string entries of varying length.
func buildStringTable(n int) [][]byte {
	entries := make([][]byte, n)
	for i := range entries {
		entries[i] = []byte(fmt.Sprintf("s%d", i))
	}
	return entries
}

// --- Tier A: micro-benchmarks ---

// A1: BlockReader.Next framing cost.
func BenchmarkBlockReaderNext(b *testing.B) {
	const (
		nFrames   = 100
		blobBytes = 256
	)
	input := buildSyntheticFrames(nFrames, blobBytes)
	rdr := bytes.NewReader(input)
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rdr.Reset(input)
		br := osmbr.NewBlockReader(rdr)
		for br.Next() {
			_ = br.Blob()
		}
		if err := br.Err(); err != nil {
			b.Fatal(err)
		}
	}
}

// A2: Decompressor raw-blob path (field 1).
func BenchmarkDecompressorRaw(b *testing.B) {
	blob := pbLenDelim(1, bytes.Repeat([]byte{0x5A}, 4096))
	var dec osmbr.Decompressor
	if _, err := dec.Decompress(blob); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(blob)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := dec.Decompress(blob); err != nil {
			b.Fatal(err)
		}
	}
}

// A3: Decompressor zlib path with raw_size (pre-sized output buffer).
func BenchmarkDecompressorZlib(b *testing.B) {
	payload := bytes.Repeat([]byte("osmbr-bench-payload-"), 256) // ~5 KiB
	blob := zlibBlob(len(payload), zlibCompress(b, payload))
	var dec osmbr.Decompressor
	if _, err := dec.Decompress(blob); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := dec.Decompress(blob); err != nil {
			b.Fatal(err)
		}
	}
}

// A4: Decompressor zlib path without raw_size (io.ReadAll branch).
func BenchmarkDecompressorZlibNoRawSize(b *testing.B) {
	payload := bytes.Repeat([]byte("osmbr-bench-payload-"), 256)
	blob := zlibBlob(-1, zlibCompress(b, payload))
	var dec osmbr.Decompressor
	if _, err := dec.Decompress(blob); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := dec.Decompress(blob); err != nil {
			b.Fatal(err)
		}
	}
}

// A5: PrimitiveBlock.DecodeFrom — stringtable scan + group defer.
func BenchmarkPrimitiveBlockDecodeFrom(b *testing.B) {
	block := primitiveBlockBytes(buildStringTable(500))
	var pb osmbr.PrimitiveBlock
	b.ReportAllocs()
	b.SetBytes(int64(len(block)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := pb.DecodeFrom(block); err != nil {
			b.Fatal(err)
		}
	}
}

// A6: GroupScanner.Next dispatch across the four group types.
func BenchmarkGroupScannerDispatch(b *testing.B) {
	// One block with four PrimitiveGroups: dense (field 2), ways (3),
	// relations (4), changesets (5). Bodies are empty — cost is dominated
	// by the peek + type discrimination.
	var extras []byte
	for _, field := range []int{2, 3, 4, 5} {
		extras = append(extras, pbLenDelim(2, pbLenDelim(field, nil))...)
	}
	block := primitiveBlockBytes([][]byte{nil}, extras...)

	var pb osmbr.PrimitiveBlock
	if err := pb.DecodeFrom(block); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(block)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gs := pb.Groups()
		for gs.Next() {
			_ = gs.Type()
		}
		if err := gs.Err(); err != nil {
			b.Fatal(err)
		}
	}
}

// A7: DecodeDenseNodes — the primary hot path for OSM reading.
func BenchmarkDecodeDenseNodes(b *testing.B) {
	group := buildDenseNodesGroup(1000, false)
	var buf osmbr.DenseNodesBuf
	if err := osmbr.DecodeDenseNodes(group, &buf, nil); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(group)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := osmbr.DecodeDenseNodes(group, &buf, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// A8: DecodeDenseNodes with DenseInfo — measures the metadata cost.
func BenchmarkDecodeDenseNodesWithInfo(b *testing.B) {
	group := buildDenseNodesGroup(1000, true)
	var (
		buf  osmbr.DenseNodesBuf
		info osmbr.DenseInfoBuf
	)
	if err := osmbr.DecodeDenseNodes(group, &buf, &info); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(group)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := osmbr.DecodeDenseNodes(group, &buf, &info); err != nil {
			b.Fatal(err)
		}
	}
}

// A9: DecodeHeader on the real OSMHeader blob from testdata.
func BenchmarkDecodeHeader(b *testing.B) {
	sets := loadTestPBFSets(b)
	if sets.headerBlock == nil {
		b.Skip("no OSMHeader block in testdata")
	}
	if _, err := osmbr.DecodeHeader(sets.headerBlock); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(sets.headerBlock)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := osmbr.DecodeHeader(sets.headerBlock); err != nil {
			b.Fatal(err)
		}
	}
}

// A10: Non-dense NodeScanner over a synthetic block.
func BenchmarkNodeScanner(b *testing.B) {
	const nNodes = 200
	block := primitiveBlockBytes([][]byte{nil}, pbLenDelim(2, buildNodesGroup(nNodes))...)
	var (
		pb   osmbr.PrimitiveBlock
		nBuf osmbr.NodeBuf
	)
	b.ReportAllocs()
	b.SetBytes(int64(len(block)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := pb.DecodeFrom(block); err != nil {
			b.Fatal(err)
		}
		gs := pb.Groups()
		if !gs.Next() {
			b.Fatalf("Groups.Next: %v", gs.Err())
		}
		ns := gs.NodeScanner()
		for _, _, _, ok := ns.Next(&nBuf, nil); ok; _, _, _, ok = ns.Next(&nBuf, nil) {
		}
		if err := ns.Err(); err != nil {
			b.Fatal(err)
		}
	}
}

// A11: WayScanner without Info.
func BenchmarkWayScanner(b *testing.B) {
	const (
		nWays = 50
		nTags = 5
		nRefs = 20
	)
	block := primitiveBlockBytes([][]byte{nil},
		pbLenDelim(2, buildWaysGroupN(nWays, nTags, nRefs, false))...)
	var (
		pb   osmbr.PrimitiveBlock
		wBuf osmbr.WayBuf
	)
	b.ReportAllocs()
	b.SetBytes(int64(len(block)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := pb.DecodeFrom(block); err != nil {
			b.Fatal(err)
		}
		gs := pb.Groups()
		if !gs.Next() {
			b.Fatalf("Groups.Next: %v", gs.Err())
		}
		ws := gs.WayScanner()
		for _, ok := ws.Next(&wBuf, nil); ok; _, ok = ws.Next(&wBuf, nil) {
		}
		if err := ws.Err(); err != nil {
			b.Fatal(err)
		}
	}
}

// A12: WayScanner with Info — quantifies decodeInfo overhead.
func BenchmarkWayScannerWithInfo(b *testing.B) {
	const (
		nWays = 50
		nTags = 5
		nRefs = 20
	)
	block := primitiveBlockBytes([][]byte{nil},
		pbLenDelim(2, buildWaysGroupN(nWays, nTags, nRefs, true))...)
	var (
		pb   osmbr.PrimitiveBlock
		wBuf osmbr.WayBuf
		iBuf osmbr.InfoBuf
	)
	b.ReportAllocs()
	b.SetBytes(int64(len(block)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := pb.DecodeFrom(block); err != nil {
			b.Fatal(err)
		}
		gs := pb.Groups()
		if !gs.Next() {
			b.Fatalf("Groups.Next: %v", gs.Err())
		}
		ws := gs.WayScanner()
		for _, ok := ws.Next(&wBuf, &iBuf); ok; _, ok = ws.Next(&wBuf, &iBuf) {
		}
		if err := ws.Err(); err != nil {
			b.Fatal(err)
		}
	}
}

// A13: RelationScanner.
func BenchmarkRelationScanner(b *testing.B) {
	const (
		nRel     = 20
		nMembers = 10
	)
	block := primitiveBlockBytes([][]byte{nil},
		pbLenDelim(2, buildRelationsGroupN(nRel, nMembers))...)
	var (
		pb   osmbr.PrimitiveBlock
		rBuf osmbr.RelationBuf
	)
	b.ReportAllocs()
	b.SetBytes(int64(len(block)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := pb.DecodeFrom(block); err != nil {
			b.Fatal(err)
		}
		gs := pb.Groups()
		if !gs.Next() {
			b.Fatalf("Groups.Next: %v", gs.Err())
		}
		rs := gs.RelationScanner()
		for _, ok := rs.Next(&rBuf, nil); ok; _, ok = rs.Next(&rBuf, nil) {
		}
		if err := rs.Err(); err != nil {
			b.Fatal(err)
		}
	}
}

// --- Tier B: end-to-end benchmarks over bundled testdata ---

// B1: BlockReader walk — isolates framing + I/O buffering cost.
func BenchmarkReadAllBlocks(b *testing.B) {
	sets := loadTestPBFSets(b)
	rdr := bytes.NewReader(sets.file)
	b.ReportAllocs()
	b.SetBytes(int64(len(sets.file)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rdr.Reset(sets.file)
		br := osmbr.NewBlockReader(rdr)
		for br.Next() {
			_ = br.Type()
			_ = br.Blob()
		}
		if err := br.Err(); err != nil {
			b.Fatal(err)
		}
	}
}

// B1b: BlockReader walk with Reset across iterations — quantifies the
// alloc floor that goes away when a consumer reuses one BlockReader
// across many files (e.g., a batch job over a directory of PBFs).
func BenchmarkReadAllBlocksReset(b *testing.B) {
	sets := loadTestPBFSets(b)
	rdr := bytes.NewReader(sets.file)
	br := osmbr.NewBlockReader(rdr)
	// Warm up: grow blobBuf to the largest block size so the timed loop
	// measures steady state.
	for br.Next() {
		_ = br.Type()
		_ = br.Blob()
	}
	if err := br.Err(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(sets.file)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rdr.Reset(sets.file)
		br.Reset(rdr)
		for br.Next() {
			_ = br.Type()
			_ = br.Blob()
		}
		if err := br.Err(); err != nil {
			b.Fatal(err)
		}
	}
}

// B2: Decompressor over preloaded OSMData blobs — isolates zlib cost.
func BenchmarkDecompressAllBlobs(b *testing.B) {
	sets := loadTestPBFSets(b)
	var total int64
	for _, blob := range sets.dataBlobs {
		total += int64(len(blob))
	}
	var dec osmbr.Decompressor
	for _, blob := range sets.dataBlobs {
		if _, err := dec.Decompress(blob); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.SetBytes(total)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, blob := range sets.dataBlobs {
			if _, err := dec.Decompress(blob); err != nil {
				b.Fatal(err)
			}
		}
	}
}

// B3: PrimitiveBlock.DecodeFrom over preloaded decompressed bytes.
func BenchmarkDecodeAllPrimitiveBlocks(b *testing.B) {
	sets := loadTestPBFSets(b)
	var total int64
	for _, data := range sets.dataBlocks {
		total += int64(len(data))
	}
	var pb osmbr.PrimitiveBlock
	b.ReportAllocs()
	b.SetBytes(total)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, data := range sets.dataBlocks {
			if err := pb.DecodeFrom(data); err != nil {
				b.Fatal(err)
			}
		}
	}
}

// B4: GroupScanner walk without entity decode.
func BenchmarkIterateAllGroups(b *testing.B) {
	sets := loadTestPBFSets(b)
	var total int64
	for _, data := range sets.dataBlocks {
		total += int64(len(data))
	}
	var pb osmbr.PrimitiveBlock
	b.ReportAllocs()
	b.SetBytes(total)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, data := range sets.dataBlocks {
			if err := pb.DecodeFrom(data); err != nil {
				b.Fatal(err)
			}
			gs := pb.Groups()
			for gs.Next() {
				_ = gs.Type()
			}
			if err := gs.Err(); err != nil {
				b.Fatal(err)
			}
		}
	}
}

// fullPipelineBufs holds all reusable state for the full-pipeline
// benchmarks. Lifting it out of the timed loop matches how real consumers
// use the library (one buffer set per worker, reused across blocks — see
// examples/count) and ensures the benchmark measures the steady-state hot
// path rather than per-iteration buffer growth. The *bytes.Reader is held
// here too so we never allocate a fresh one per iteration; production
// callers typically pass an already-allocated *os.File, so counting a
// reader alloc per file-read would misrepresent real-world cost.
type fullPipelineBufs struct {
	rdr   *bytes.Reader
	dec   osmbr.Decompressor
	pb    osmbr.PrimitiveBlock
	dnBuf osmbr.DenseNodesBuf
	nBuf  osmbr.NodeBuf
	wBuf  osmbr.WayBuf
	rBuf  osmbr.RelationBuf
	iBuf  osmbr.InfoBuf
	diBuf osmbr.DenseInfoBuf
}

// B5: Full pipeline without Info — the canonical regression anchor.
// Mirrors the decode path in examples/count, serialized into one goroutine.
func BenchmarkReadFullNoInfo(b *testing.B) {
	sets := loadTestPBFSets(b)
	var bufs fullPipelineBufs
	runFullPipeline(b, sets.file, &bufs, false) // warm up
	b.ReportAllocs()
	b.SetBytes(int64(len(sets.file)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runFullPipeline(b, sets.file, &bufs, false)
	}
}

// B6: Full pipeline with Info buffers — quantifies metadata cost.
func BenchmarkReadFullWithInfo(b *testing.B) {
	sets := loadTestPBFSets(b)
	var bufs fullPipelineBufs
	runFullPipeline(b, sets.file, &bufs, true) // warm up
	b.ReportAllocs()
	b.SetBytes(int64(len(sets.file)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runFullPipeline(b, sets.file, &bufs, true)
	}
}

// runFullPipeline walks the entire file through BlockReader → Decompressor →
// PrimitiveBlock.DecodeFrom → GroupScanner → per-type entity decode, reusing
// the caller-provided bufs so steady-state allocation behaviour is visible.
func runFullPipeline(b *testing.B, file []byte, bufs *fullPipelineBufs, withInfo bool) {
	b.Helper()
	var (
		ip    *osmbr.InfoBuf
		diPtr *osmbr.DenseInfoBuf
	)
	if withInfo {
		ip = &bufs.iBuf
		diPtr = &bufs.diBuf
	}
	if bufs.rdr == nil {
		bufs.rdr = bytes.NewReader(file)
	} else {
		bufs.rdr.Reset(file)
	}
	br := osmbr.NewBlockReader(bufs.rdr)
	for br.Next() {
		if br.Type() != "OSMData" {
			continue
		}
		data, err := bufs.dec.Decompress(br.Blob())
		if err != nil {
			b.Fatal(err)
		}
		if err := bufs.pb.DecodeFrom(data); err != nil {
			b.Fatal(err)
		}
		gs := bufs.pb.Groups()
		for gs.Next() {
			switch gs.Type() {
			case osmbr.GroupTypeDense:
				if err := gs.DecodeDenseNodes(&bufs.dnBuf, diPtr); err != nil {
					b.Fatal(err)
				}
			case osmbr.GroupTypeNodes:
				ns := gs.NodeScanner()
				for _, _, _, ok := ns.Next(&bufs.nBuf, ip); ok; _, _, _, ok = ns.Next(&bufs.nBuf, ip) {
				}
				if err := ns.Err(); err != nil {
					b.Fatal(err)
				}
			case osmbr.GroupTypeWays:
				ws := gs.WayScanner()
				for _, ok := ws.Next(&bufs.wBuf, ip); ok; _, ok = ws.Next(&bufs.wBuf, ip) {
				}
				if err := ws.Err(); err != nil {
					b.Fatal(err)
				}
			case osmbr.GroupTypeRelations:
				rs := gs.RelationScanner()
				for _, ok := rs.Next(&bufs.rBuf, ip); ok; _, ok = rs.Next(&bufs.rBuf, ip) {
				}
				if err := rs.Err(); err != nil {
					b.Fatal(err)
				}
			}
		}
		if err := gs.Err(); err != nil {
			b.Fatal(err)
		}
	}
	if err := br.Err(); err != nil {
		b.Fatal(err)
	}
}
