package osmbr_test

import (
	"slices"
	"testing"

	"github.com/invisiblefunnel/osmbr"
)

// wayBytes builds a Way submessage body with the given id, tags, and refs.
// keys/vals are string-table indices. refs is pre-delta-encoded.
func wayBytes(id int64, keys, vals []uint32, refs []int64) []byte {
	body := pbVarintField(1, uint64(id)) // id (int64)
	if len(keys) > 0 {
		body = append(body, pbPackedUint32(2, keys)...)
	}
	if len(vals) > 0 {
		body = append(body, pbPackedUint32(3, vals)...)
	}
	if len(refs) > 0 {
		body = append(body, pbPackedSint64(8, refs)...)
	}
	return body
}

// waysGroup wraps each way body as field 3 of a PrimitiveGroup.
func waysGroup(ways ...[]byte) []byte {
	var group []byte
	for _, w := range ways {
		group = append(group, pbLenDelim(3, w)...)
	}
	return group
}

func TestWayScannerNext(t *testing.T) {
	// Two ways with different tags and refs.
	w1 := wayBytes(100, []uint32{1, 3}, []uint32{2, 4}, []int64{10, 5, -3}) // refs → 10, 15, 12
	w2 := wayBytes(200, nil, nil, []int64{42})

	block := primitiveBlockBytes([][]byte{nil}, pbLenDelim(2, waysGroup(w1, w2))...)

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
	if gs.Type() != osmbr.GroupTypeWays {
		t.Fatalf("Type = %v, want GroupTypeWays", gs.Type())
	}

	ws := gs.WayScanner()

	id1, ok := ws.Next(&wBuf, nil)
	if !ok {
		t.Fatalf("first Next: %v", ws.Err())
	}
	if id1 != 100 {
		t.Errorf("id = %d, want 100", id1)
	}
	if !slices.Equal(wBuf.Keys, []uint32{1, 3}) {
		t.Errorf("Keys = %v", wBuf.Keys)
	}
	if !slices.Equal(wBuf.Vals, []uint32{2, 4}) {
		t.Errorf("Vals = %v", wBuf.Vals)
	}
	if !slices.Equal(wBuf.Refs, []int64{10, 15, 12}) {
		t.Errorf("Refs = %v, want delta-decoded [10 15 12]", wBuf.Refs)
	}

	id2, ok := ws.Next(&wBuf, nil)
	if !ok {
		t.Fatalf("second Next: %v", ws.Err())
	}
	if id2 != 200 {
		t.Errorf("id = %d, want 200", id2)
	}
	if len(wBuf.Keys) != 0 || len(wBuf.Vals) != 0 {
		t.Errorf("expected empty tags on second way")
	}
	if !slices.Equal(wBuf.Refs, []int64{42}) {
		t.Errorf("Refs = %v, want [42]", wBuf.Refs)
	}

	if _, ok := ws.Next(&wBuf, nil); ok {
		t.Errorf("third Next returned ok, want end-of-iteration")
	}
	if err := ws.Err(); err != nil {
		t.Errorf("Err = %v, want nil", err)
	}
}

func TestWayScannerEmptyGroup(t *testing.T) {
	// PrimitiveGroup with no Way entries.
	block := primitiveBlockBytes([][]byte{nil}, pbLenDelim(2, pbLenDelim(3, nil))...)

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
	// A zero-length Way body is legal and yields id=0, but then no further ways.
	if ok && id != 0 {
		t.Errorf("empty way yielded id = %d", id)
	}
}

func TestWayScannerBufferReuse(t *testing.T) {
	w1 := wayBytes(1, []uint32{1, 2, 3}, []uint32{4, 5, 6}, []int64{1, 1, 1})
	w2 := wayBytes(2, nil, nil, []int64{10})

	block := primitiveBlockBytes([][]byte{nil}, pbLenDelim(2, waysGroup(w1, w2))...)

	var (
		pb   osmbr.PrimitiveBlock
		wBuf osmbr.WayBuf
	)
	if err := pb.DecodeFrom(block); err != nil {
		t.Fatalf("DecodeFrom: %v", err)
	}
	gs := pb.Groups()
	if !gs.Next() {
		t.Fatal("Groups.Next returned false")
	}
	ws := gs.WayScanner()
	if _, ok := ws.Next(&wBuf, nil); !ok {
		t.Fatalf("first Next: %v", ws.Err())
	}
	firstCap := cap(wBuf.Keys)
	if _, ok := ws.Next(&wBuf, nil); !ok {
		t.Fatalf("second Next: %v", ws.Err())
	}
	// Keys/Vals should be reset to len 0; underlying capacity preserved.
	if len(wBuf.Keys) != 0 || len(wBuf.Vals) != 0 {
		t.Errorf("expected empty keys/vals after second way, got Keys=%v Vals=%v",
			wBuf.Keys, wBuf.Vals)
	}
	if cap(wBuf.Keys) < firstCap {
		t.Errorf("capacity shrank: first=%d, second=%d", firstCap, cap(wBuf.Keys))
	}
}
