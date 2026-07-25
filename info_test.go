package osmbr_test

import (
	"slices"
	"testing"

	"github.com/invisiblefunnel/osmbr"
)

// wayWithInfoGroup wraps a single Way (field 3) around an Info submessage
// (field 4) so that WayScanner exercises decodeInfo.
func wayWithInfoGroup(infoBody []byte) []byte {
	way := pbVarintField(1, 99) // id = 99
	if infoBody != nil {
		way = append(way, pbLenDelim(4, infoBody)...)
	}
	return pbLenDelim(3, way)
}

func TestInfoBufAllFields(t *testing.T) {
	info := pbVarintField(1, 7)                          // version
	info = append(info, pbVarintField(2, 1700000000)...) // timestamp
	info = append(info, pbVarintField(3, 42)...)         // changeset
	info = append(info, pbVarintField(4, 100)...)        // uid
	info = append(info, pbVarintField(5, 3)...)          // user_sid
	info = append(info, pbVarintField(6, 1)...)          // visible = true

	block := primitiveBlockBytes([][]byte{nil}, pbLenDelim(2, wayWithInfoGroup(info))...)

	var (
		pb   osmbr.PrimitiveBlock
		wBuf osmbr.WayBuf
		iBuf osmbr.InfoBuf
	)
	if err := pb.DecodeFrom(block); err != nil {
		t.Fatalf("DecodeFrom: %v", err)
	}
	gs := pb.Groups()
	if !gs.Next() {
		t.Fatalf("Groups.Next: %v", gs.Err())
	}
	ws := gs.WayScanner()
	if _, ok := ws.Next(&wBuf, &iBuf); !ok {
		t.Fatalf("WayScanner.Next returned false: %v", ws.Err())
	}

	want := osmbr.InfoBuf{
		Version: 7, Timestamp: 1700000000, Changeset: 42,
		UID: 100, UserSID: 3, Visible: true, HasVisible: true,
	}
	if iBuf != want {
		t.Errorf("InfoBuf = %+v, want %+v", iBuf, want)
	}
}

func TestInfoBufVisibleAbsent(t *testing.T) {
	// Info message without a visible field.
	info := pbVarintField(1, 1)
	block := primitiveBlockBytes([][]byte{nil}, pbLenDelim(2, wayWithInfoGroup(info))...)

	var (
		pb   osmbr.PrimitiveBlock
		wBuf osmbr.WayBuf
		iBuf osmbr.InfoBuf
	)
	if err := pb.DecodeFrom(block); err != nil {
		t.Fatalf("DecodeFrom: %v", err)
	}
	gs := pb.Groups()
	if !gs.Next() {
		t.Fatalf("Groups.Next: %v", gs.Err())
	}
	ws := gs.WayScanner()
	if _, ok := ws.Next(&wBuf, &iBuf); !ok {
		t.Fatalf("WayScanner.Next: %v", ws.Err())
	}
	if iBuf.HasVisible {
		t.Errorf("HasVisible = true, want false")
	}
	if iBuf.Visible {
		t.Errorf("Visible = true, want false (absent)")
	}
}

// TestInfoBufEmpty covers a Way with no Info field at all. Next must zero the
// buffer rather than leave whatever it held, since the caller cannot otherwise
// tell metadata-free from stale.
func TestInfoBufEmpty(t *testing.T) {
	block := primitiveBlockBytes([][]byte{nil}, pbLenDelim(2, wayWithInfoGroup(nil))...)

	var (
		pb   osmbr.PrimitiveBlock
		wBuf osmbr.WayBuf
	)
	iBuf := osmbr.InfoBuf{Version: 999, Changeset: 7, HasVisible: true}
	if err := pb.DecodeFrom(block); err != nil {
		t.Fatalf("DecodeFrom: %v", err)
	}
	gs := pb.Groups()
	if !gs.Next() {
		t.Fatalf("Groups.Next: %v", gs.Err())
	}
	ws := gs.WayScanner()
	if _, ok := ws.Next(&wBuf, &iBuf); !ok {
		t.Fatalf("WayScanner.Next: %v", ws.Err())
	}
	if iBuf != (osmbr.InfoBuf{}) {
		t.Errorf("InfoBuf = %+v, want the zero value", iBuf)
	}
}

// TestInfoBufNotStaleAcrossEntities is the same reset across a scan: a Way
// carrying Info followed by one without must not report the first way's
// metadata for the second.
func TestInfoBufNotStaleAcrossEntities(t *testing.T) {
	info := pbVarintField(1, 42)                  // version
	info = append(info, pbVarintField(3, 999)...) // changeset
	group := wayWithInfoGroup(info)
	group = append(group, wayWithInfoGroup(nil)...)
	block := primitiveBlockBytes([][]byte{nil}, pbLenDelim(2, group)...)

	var (
		pb   osmbr.PrimitiveBlock
		wBuf osmbr.WayBuf
		iBuf osmbr.InfoBuf
	)
	if err := pb.DecodeFrom(block); err != nil {
		t.Fatalf("DecodeFrom: %v", err)
	}
	gs := pb.Groups()
	if !gs.Next() {
		t.Fatalf("Groups.Next: %v", gs.Err())
	}
	ws := gs.WayScanner()

	if _, ok := ws.Next(&wBuf, &iBuf); !ok {
		t.Fatalf("first Next: %v", ws.Err())
	}
	if iBuf.Version != 42 || iBuf.Changeset != 999 {
		t.Fatalf("first way: InfoBuf = %+v, want version 42 changeset 999", iBuf)
	}

	if _, ok := ws.Next(&wBuf, &iBuf); !ok {
		t.Fatalf("second Next: %v", ws.Err())
	}
	if iBuf != (osmbr.InfoBuf{}) {
		t.Errorf("second way has no Info but InfoBuf = %+v, want the zero value", iBuf)
	}
	if err := ws.Err(); err != nil {
		t.Fatalf("Err: %v", err)
	}
}

func TestInfoSkipWhenInfoArgNil(t *testing.T) {
	// Passing nil info must skip the Info field without error.
	info := pbVarintField(1, 3)
	block := primitiveBlockBytes([][]byte{nil}, pbLenDelim(2, wayWithInfoGroup(info))...)

	var (
		pb   osmbr.PrimitiveBlock
		wBuf osmbr.WayBuf
	)
	if err := pb.DecodeFrom(block); err != nil {
		t.Fatalf("DecodeFrom: %v", err)
	}
	gs := pb.Groups()
	if !gs.Next() {
		t.Fatalf("Groups.Next: %v", gs.Err())
	}
	ws := gs.WayScanner()
	id, ok := ws.Next(&wBuf, nil)
	if !ok {
		t.Fatalf("WayScanner.Next: %v", ws.Err())
	}
	if id != 99 {
		t.Errorf("id = %d, want 99", id)
	}
}

func TestDenseInfoBufDeltaDecode(t *testing.T) {
	// Three nodes with non-delta versions/user_sids and delta timestamps/changesets/uids.
	versions := []int32{1, 2, 3}
	timestamps := []int64{100, 10, 20} // → 100, 110, 130
	changesets := []int64{50, 5, 5}    // → 50, 55, 60
	uids := []int32{10, 1, 2}          // → 10, 11, 13
	userSIDs := []uint32{4, 5, 6}
	visibles := []bool{true, false, true}

	diBody := pbPackedInt32(1, versions)
	diBody = append(diBody, pbPackedSint64(2, timestamps)...)
	diBody = append(diBody, pbPackedSint64(3, changesets)...)
	diBody = append(diBody, pbPackedSint32(4, uids)...)
	diBody = append(diBody, pbPackedUint32(5, userSIDs)...)
	diBody = append(diBody, pbPackedBool(6, visibles)...)

	// Three nodes with zero coordinates so the DenseNodesBuf length matches.
	group := denseGroupBytes([]int64{1, 0, 0}, []int64{0, 0, 0}, []int64{0, 0, 0}, nil, diBody)

	var (
		buf  osmbr.DenseNodesBuf
		info osmbr.DenseInfoBuf
	)
	if err := osmbr.DecodeDenseNodes(group, &buf, &info); err != nil {
		t.Fatalf("DecodeDenseNodes: %v", err)
	}

	if !slices.Equal(info.Versions, versions) {
		t.Errorf("Versions = %v, want %v", info.Versions, versions)
	}
	if !slices.Equal(info.Timestamps, []int64{100, 110, 130}) {
		t.Errorf("Timestamps = %v, want delta-decoded", info.Timestamps)
	}
	if !slices.Equal(info.Changesets, []int64{50, 55, 60}) {
		t.Errorf("Changesets = %v, want delta-decoded", info.Changesets)
	}
	if !slices.Equal(info.UIDs, []int32{10, 11, 13}) {
		t.Errorf("UIDs = %v, want delta-decoded", info.UIDs)
	}
	if !slices.Equal(info.UserSIDs, userSIDs) {
		t.Errorf("UserSIDs = %v, want %v", info.UserSIDs, userSIDs)
	}
	if !slices.Equal(info.Visibles, visibles) {
		t.Errorf("Visibles = %v, want %v", info.Visibles, visibles)
	}
}

func TestDenseInfoBufDeltaDecodeMixedPackedAndUnpacked(t *testing.T) {
	diBody := pbPackedInt32(1, []int32{1, 2, 3})
	diBody = append(diBody, pbPackedSint64(2, []int64{100, 10})...)
	diBody = append(diBody, pbSint64Field(2, 20)...)
	diBody = append(diBody, pbPackedSint64(3, []int64{50, 5})...)
	diBody = append(diBody, pbSint64Field(3, 5)...)
	diBody = append(diBody, pbPackedSint32(4, []int32{10, 1})...)
	diBody = append(diBody, pbSint32Field(4, 2)...)

	group := denseGroupBytes([]int64{1, 0, 0}, []int64{0, 0, 0}, []int64{0, 0, 0}, nil, diBody)

	var (
		buf  osmbr.DenseNodesBuf
		info osmbr.DenseInfoBuf
	)
	if err := osmbr.DecodeDenseNodes(group, &buf, &info); err != nil {
		t.Fatalf("DecodeDenseNodes: %v", err)
	}
	if !slices.Equal(info.Timestamps, []int64{100, 110, 130}) {
		t.Errorf("Timestamps = %v, want mixed-field delta decode", info.Timestamps)
	}
	if !slices.Equal(info.Changesets, []int64{50, 55, 60}) {
		t.Errorf("Changesets = %v, want mixed-field delta decode", info.Changesets)
	}
	if !slices.Equal(info.UIDs, []int32{10, 11, 13}) {
		t.Errorf("UIDs = %v, want mixed-field delta decode", info.UIDs)
	}
}
