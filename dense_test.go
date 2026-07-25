package osmbr_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/invisiblefunnel/osmbr"
)

// denseGroupBytes builds a PrimitiveGroup body containing a DenseNodes
// submessage with the given (pre-delta-encoded) slices. denseInfo, if
// non-nil, is embedded as field 5.
func denseGroupBytes(ids, lats, lons []int64, keysVals []int32, denseInfo []byte) []byte {
	dense := pbPackedSint64(1, ids)
	dense = append(dense, pbPackedSint64(8, lats)...)
	dense = append(dense, pbPackedSint64(9, lons)...)
	if len(keysVals) > 0 {
		dense = append(dense, pbPackedInt32(10, keysVals)...)
	}
	if denseInfo != nil {
		dense = append(dense, pbLenDelim(5, denseInfo)...)
	}
	return pbLenDelim(2, dense) // field 2 of PrimitiveGroup
}

func TestDecodeDenseNodesDeltaDecode(t *testing.T) {
	// Delta-encoded inputs; expected absolute values after delta decoding.
	ids := []int64{10, 5, -3} // 10, 15, 12
	lats := []int64{100, 10, 10}
	lons := []int64{200, -20, 30}
	want := struct {
		ids  []int64
		lats []int64
		lons []int64
	}{
		ids:  []int64{10, 15, 12},
		lats: []int64{100, 110, 120},
		lons: []int64{200, 180, 210},
	}

	group := denseGroupBytes(ids, lats, lons, nil, nil)

	var buf osmbr.DenseNodesBuf
	if err := osmbr.DecodeDenseNodes(group, &buf, nil); err != nil {
		t.Fatalf("DecodeDenseNodes: %v", err)
	}
	if !slices.Equal(buf.IDs, want.ids) {
		t.Errorf("IDs = %v, want %v", buf.IDs, want.ids)
	}
	if !slices.Equal(buf.Lats, want.lats) {
		t.Errorf("Lats = %v, want %v", buf.Lats, want.lats)
	}
	if !slices.Equal(buf.Lons, want.lons) {
		t.Errorf("Lons = %v, want %v", buf.Lons, want.lons)
	}
}

func TestDecodeDenseNodesDeltaDecodeMixedPackedAndUnpacked(t *testing.T) {
	var dense []byte
	dense = append(dense, pbPackedSint64(1, []int64{10, 5})...)
	dense = append(dense, pbSint64Field(1, -3)...)
	dense = append(dense, pbPackedSint64(8, []int64{100, 10})...)
	dense = append(dense, pbSint64Field(8, 10)...)
	dense = append(dense, pbPackedSint64(9, []int64{200, -20})...)
	dense = append(dense, pbSint64Field(9, 30)...)
	group := pbLenDelim(2, dense)

	var buf osmbr.DenseNodesBuf
	if err := osmbr.DecodeDenseNodes(group, &buf, nil); err != nil {
		t.Fatalf("DecodeDenseNodes: %v", err)
	}
	if !slices.Equal(buf.IDs, []int64{10, 15, 12}) {
		t.Errorf("IDs = %v, want mixed-field delta decode", buf.IDs)
	}
	if !slices.Equal(buf.Lats, []int64{100, 110, 120}) {
		t.Errorf("Lats = %v, want mixed-field delta decode", buf.Lats)
	}
	if !slices.Equal(buf.Lons, []int64{200, 180, 210}) {
		t.Errorf("Lons = %v, want mixed-field delta decode", buf.Lons)
	}
}

func TestDecodeDenseNodesWithKeysVals(t *testing.T) {
	// Two nodes. Node A has one tag (1→2), node B has two tags (3→4, 5→6).
	keysVals := []int32{1, 2, 0, 3, 4, 5, 6, 0}
	group := denseGroupBytes([]int64{1, 1}, []int64{0, 0}, []int64{0, 0}, keysVals, nil)

	var buf osmbr.DenseNodesBuf
	if err := osmbr.DecodeDenseNodes(group, &buf, nil); err != nil {
		t.Fatalf("DecodeDenseNodes: %v", err)
	}
	if !slices.Equal(buf.KeysVals, keysVals) {
		t.Errorf("KeysVals = %v, want %v", buf.KeysVals, keysVals)
	}
}

func TestDecodeDenseNodesLengthMismatch(t *testing.T) {
	// IDs has 3 entries, Lats has 2 — should be rejected.
	group := denseGroupBytes([]int64{1, 1, 1}, []int64{1, 1}, []int64{1, 1, 1}, nil, nil)

	var buf osmbr.DenseNodesBuf
	err := osmbr.DecodeDenseNodes(group, &buf, nil)
	if err == nil {
		t.Fatal("expected length-mismatch error")
	}
	if !strings.Contains(err.Error(), "length mismatch") {
		t.Errorf("error %q lacks 'length mismatch'", err)
	}
}

// TestDecodeDenseNodesInfoLengthMismatch rejects a DenseInfo whose arrays do
// not line up with the node arrays. Callers index these by node position, so a
// mismatched array would otherwise panic at the call site instead of failing
// here.
func TestDecodeDenseNodesInfoLengthMismatch(t *testing.T) {
	ids := []int64{1, 1, 1} // 3 nodes
	cases := []struct {
		name  string
		info  []byte
		field string
	}{
		{"short version", pbPackedInt32(1, []int32{1}), "version"},
		{"short timestamp", pbPackedSint64(2, []int64{1, 1}), "timestamp"},
		{"short changeset", pbPackedSint64(3, []int64{1}), "changeset"},
		{"short uid", pbPackedSint32(4, []int32{1}), "uid"},
		{"short user_sid", pbPackedUint32(5, []uint32{1}), "user_sid"},
		{"short visible", pbPackedBool(6, []bool{true}), "visible"},
		{"long version", pbPackedInt32(1, []int32{1, 1, 1, 1}), "version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			group := denseGroupBytes(ids, ids, ids, nil, tc.info)
			var (
				buf  osmbr.DenseNodesBuf
				info osmbr.DenseInfoBuf
			)
			err := osmbr.DecodeDenseNodes(group, &buf, &info)
			if err == nil {
				t.Fatal("expected a DenseInfo length-mismatch error")
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("error %q does not name the %s field", err, tc.field)
			}
		})
	}
}

// TestDecodeDenseNodesInfoAbsentArraysOK allows the arrays a file legitimately
// omits: visible only appears in full-history extracts, so absent must stay
// distinct from short.
func TestDecodeDenseNodesInfoAbsentArraysOK(t *testing.T) {
	ids := []int64{1, 1, 1}
	info := pbPackedInt32(1, []int32{4, 5, 6})
	info = append(info, pbPackedSint64(2, []int64{1, 1, 1})...)
	// changeset, uid, user_sid and visible are all absent.

	group := denseGroupBytes(ids, ids, ids, nil, info)
	var (
		buf osmbr.DenseNodesBuf
		di  osmbr.DenseInfoBuf
	)
	if err := osmbr.DecodeDenseNodes(group, &buf, &di); err != nil {
		t.Fatalf("DecodeDenseNodes: %v", err)
	}
	if len(di.Versions) != 3 || len(di.Timestamps) != 3 {
		t.Errorf("Versions=%d Timestamps=%d, want 3 each", len(di.Versions), len(di.Timestamps))
	}
	if len(di.Changesets) != 0 || len(di.Visibles) != 0 {
		t.Errorf("absent arrays should stay empty: Changesets=%d Visibles=%d",
			len(di.Changesets), len(di.Visibles))
	}
	// The guarantee callers rely on: any non-empty array indexes by node.
	for i := range buf.IDs {
		_ = di.Versions[i]
		_ = di.Timestamps[i]
	}
}

func TestDecodeDenseNodesEmptyGroup(t *testing.T) {
	// No DenseNodes submessage at all.
	var buf osmbr.DenseNodesBuf
	if err := osmbr.DecodeDenseNodes(nil, &buf, nil); err != nil {
		t.Fatalf("DecodeDenseNodes(nil): %v", err)
	}
	if len(buf.IDs) != 0 || len(buf.Lats) != 0 || len(buf.Lons) != 0 {
		t.Errorf("expected empty buf, got IDs=%d Lats=%d Lons=%d",
			len(buf.IDs), len(buf.Lats), len(buf.Lons))
	}
}

func TestDecodeDenseNodesReuseClears(t *testing.T) {
	first := denseGroupBytes([]int64{10}, []int64{20}, []int64{30}, []int32{1, 2, 0}, nil)
	second := denseGroupBytes([]int64{100}, []int64{200}, []int64{300}, nil, nil)

	var buf osmbr.DenseNodesBuf
	if err := osmbr.DecodeDenseNodes(first, &buf, nil); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := osmbr.DecodeDenseNodes(second, &buf, nil); err != nil {
		t.Fatalf("second: %v", err)
	}
	if !slices.Equal(buf.IDs, []int64{100}) {
		t.Errorf("IDs after reuse = %v, want [100]", buf.IDs)
	}
	if len(buf.KeysVals) != 0 {
		t.Errorf("KeysVals after reuse = %v, want empty", buf.KeysVals)
	}
}

// TestDecodeDenseNodesInfoReuseClears covers a DenseInfoBuf reused across a
// group that carries DenseInfo and one that does not. denseinfo is an optional
// field, so nothing in the second group's bytes overwrites the arrays; only an
// up-front reset stops the caller reading the first group's metadata against
// the second group's nodes.
func TestDecodeDenseNodesInfoReuseClears(t *testing.T) {
	ids := []int64{1, 1, 1}
	info := pbPackedInt32(1, []int32{7, 8, 9})
	info = append(info, pbPackedSint64(2, []int64{5, 5, 5})...)
	withInfo := denseGroupBytes(ids, ids, ids, nil, info)

	var (
		buf osmbr.DenseNodesBuf
		di  osmbr.DenseInfoBuf
	)
	if err := osmbr.DecodeDenseNodes(withInfo, &buf, &di); err != nil {
		t.Fatalf("group with DenseInfo: %v", err)
	}
	if !slices.Equal(di.Versions, []int32{7, 8, 9}) {
		t.Fatalf("Versions = %v, want [7 8 9]", di.Versions)
	}

	// Same node count: a stale array is exactly as long as the new node arrays,
	// so the length check cannot catch it.
	sameCount := denseGroupBytes(ids, ids, ids, nil, nil)
	if err := osmbr.DecodeDenseNodes(sameCount, &buf, &di); err != nil {
		t.Fatalf("metadata-free group, same node count: %v", err)
	}
	if len(di.Versions) != 0 || len(di.Timestamps) != 0 {
		t.Errorf("stale metadata after a group with no DenseInfo: Versions=%v Timestamps=%v",
			di.Versions, di.Timestamps)
	}

	// Different node count: a stale array used to fail the length check and
	// reject a legal metadata-free group.
	if err := osmbr.DecodeDenseNodes(withInfo, &buf, &di); err != nil {
		t.Fatalf("group with DenseInfo: %v", err)
	}
	five := []int64{1, 1, 1, 1, 1}
	if err := osmbr.DecodeDenseNodes(denseGroupBytes(five, five, five, nil, nil), &buf, &di); err != nil {
		t.Errorf("metadata-free group, different node count: %v", err)
	}
	if len(di.Versions) != 0 {
		t.Errorf("Versions = %v, want empty", di.Versions)
	}
}

// TestDecodeDenseNodesInfoClearedOnNonDenseGroup covers the same reset for a
// group with no DenseNodes submessage at all.
func TestDecodeDenseNodesInfoClearedOnNonDenseGroup(t *testing.T) {
	ids := []int64{1, 1, 1}
	withInfo := denseGroupBytes(ids, ids, ids, nil, pbPackedInt32(1, []int32{7, 8, 9}))

	var (
		buf osmbr.DenseNodesBuf
		di  osmbr.DenseInfoBuf
	)
	if err := osmbr.DecodeDenseNodes(withInfo, &buf, &di); err != nil {
		t.Fatalf("group with DenseInfo: %v", err)
	}
	if err := osmbr.DecodeDenseNodes(nil, &buf, &di); err != nil {
		t.Fatalf("empty group: %v", err)
	}
	if len(di.Versions) != 0 {
		t.Errorf("Versions = %v after an empty group, want empty", di.Versions)
	}
}

// TestDecodeDenseNodesInfoSplitAcrossEntries covers a DenseInfo submessage
// split over two wire entries. Protobuf merges repeated occurrences of a
// singular message field, so the halves must concatenate into one set of
// per-node arrays rather than the second replacing the first.
func TestDecodeDenseNodesInfoSplitAcrossEntries(t *testing.T) {
	ids := []int64{1, 1, 1, 1}
	first := pbPackedInt32(1, []int32{7, 8})
	second := pbPackedInt32(1, []int32{9, 10})

	// denseGroupBytes wraps info in a single field 5; build the split form here.
	var dense []byte
	dense = append(dense, pbPackedSint64(1, ids)...)
	dense = append(dense, pbPackedSint64(8, ids)...)
	dense = append(dense, pbPackedSint64(9, ids)...)
	dense = append(dense, pbLenDelim(5, first)...)
	dense = append(dense, pbLenDelim(5, second)...)
	group := pbLenDelim(2, dense)

	var (
		buf osmbr.DenseNodesBuf
		di  osmbr.DenseInfoBuf
	)
	if err := osmbr.DecodeDenseNodes(group, &buf, &di); err != nil {
		t.Fatalf("DecodeDenseNodes: %v", err)
	}
	if !slices.Equal(di.Versions, []int32{7, 8, 9, 10}) {
		t.Errorf("Versions = %v, want [7 8 9 10]", di.Versions)
	}
	if len(di.Versions) != len(buf.IDs) {
		t.Errorf("Versions has %d entries for %d nodes", len(di.Versions), len(buf.IDs))
	}
}
