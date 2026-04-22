package osmbr_test

import (
	"testing"

	"github.com/invisiblefunnel/osmbr"
)

func TestGroupScannerDispatch(t *testing.T) {
	// Build one PrimitiveBlock containing four PrimitiveGroups, each with a
	// single marker field that lets GroupScanner identify the type. Skip
	// GroupTypeNodes here — that case is covered in node_test.go.
	cases := []struct {
		name    string
		field   int // primitivegroup field number for the marker
		want    osmbr.GroupType
		content []byte
	}{
		{"dense", 2, osmbr.GroupTypeDense, pbLenDelim(2, nil)},
		{"ways", 3, osmbr.GroupTypeWays, pbLenDelim(3, nil)},
		{"relations", 4, osmbr.GroupTypeRelations, pbLenDelim(4, nil)},
		{"changesets", 5, osmbr.GroupTypeChangesets, pbLenDelim(5, nil)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			block := primitiveBlockBytes([][]byte{nil}, pbLenDelim(2, tc.content)...)

			var pb osmbr.PrimitiveBlock
			if err := pb.DecodeFrom(block); err != nil {
				t.Fatalf("DecodeFrom: %v", err)
			}
			gs := pb.Groups()
			if !gs.Next() {
				t.Fatalf("Groups.Next = false: %v", gs.Err())
			}
			if gs.Type() != tc.want {
				t.Errorf("Type = %v, want %v", gs.Type(), tc.want)
			}
			if gs.Next() {
				t.Errorf("unexpected second group")
			}
		})
	}
}

func TestGroupScannerEmptyBlock(t *testing.T) {
	// Block with only a stringtable — no primitivegroup.
	block := primitiveBlockBytes([][]byte{nil})

	var pb osmbr.PrimitiveBlock
	if err := pb.DecodeFrom(block); err != nil {
		t.Fatalf("DecodeFrom: %v", err)
	}
	gs := pb.Groups()
	if gs.Next() {
		t.Fatalf("Groups.Next = true, want false for block with no groups")
	}
	if err := gs.Err(); err != nil {
		t.Errorf("Err = %v, want nil", err)
	}
}

func TestGroupScannerEmptyGroup(t *testing.T) {
	// A PrimitiveGroup with no fields at all → GroupTypeUnknown.
	block := primitiveBlockBytes([][]byte{nil}, pbLenDelim(2, nil)...)

	var pb osmbr.PrimitiveBlock
	if err := pb.DecodeFrom(block); err != nil {
		t.Fatalf("DecodeFrom: %v", err)
	}
	gs := pb.Groups()
	if !gs.Next() {
		t.Fatalf("Groups.Next = false: %v", gs.Err())
	}
	if gs.Type() != osmbr.GroupTypeUnknown {
		t.Errorf("Type = %v, want GroupTypeUnknown for empty group", gs.Type())
	}
}
