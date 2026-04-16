package osmbr_test

import (
	"testing"

	"github.com/invisiblefunnel/osmbr"
)

// pbZigzag returns the protobuf zig-zag encoding of n.
func pbZigzag(n int64) uint64 {
	return uint64((n << 1) ^ (n >> 63))
}

// pbSint64Field returns a sint64 field encoding.
func pbSint64Field(fieldNumber int, value int64) []byte {
	return pbVarintField(fieldNumber, pbZigzag(value))
}

// TestNodeScannerNonDense exercises NodeScanner against a synthetic
// PrimitiveBlock that uses non-dense Node messages (rare in real data —
// the bundled test file uses only DenseNodes).
func TestNodeScannerNonDense(t *testing.T) {
	type sample struct {
		id, lat, lon int64
	}
	want := []sample{
		{id: 1, lat: 100, lon: 200},
		{id: 42, lat: -300, lon: 400},
	}

	// Build a Nodes PrimitiveGroup containing each Node as field 1.
	var group []byte
	for _, s := range want {
		node := pbSint64Field(1, s.id)
		node = append(node, pbSint64Field(8, s.lat)...)
		node = append(node, pbSint64Field(9, s.lon)...)
		group = append(group, pbLenDelim(1, node)...)
	}

	// Wrap in a PrimitiveBlock with an empty stringtable (field 1) and
	// the group (field 2).
	block := pbLenDelim(1, pbLenDelim(1, nil)) // stringtable with one empty entry
	block = append(block, pbLenDelim(2, group)...)

	var pb osmbr.PrimitiveBlock
	if err := pb.DecodeFrom(block); err != nil {
		t.Fatalf("DecodeFrom: %v", err)
	}

	gs := pb.Groups()
	if !gs.Next() {
		t.Fatalf("Groups.Next returned false: %v", gs.Err())
	}
	if gs.Type() != osmbr.GroupTypeNodes {
		t.Fatalf("Type = %v, want GroupTypeNodes", gs.Type())
	}

	var buf osmbr.NodeBuf
	ns := gs.NodeScanner()

	var got []sample
	for id, lat, lon, ok := ns.Next(&buf, nil); ok; id, lat, lon, ok = ns.Next(&buf, nil) {
		got = append(got, sample{id: id, lat: lat, lon: lon})
	}
	if err := ns.Err(); err != nil {
		t.Fatalf("NodeScanner.Err: %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("got %d nodes, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("node %d: got %+v, want %+v", i, got[i], w)
		}
	}
}
