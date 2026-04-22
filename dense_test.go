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
