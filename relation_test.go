package osmbr_test

import (
	"slices"
	"testing"

	"github.com/invisiblefunnel/osmbr"
)

// relationBytes builds a Relation submessage body.
// memids is pre-delta-encoded.
func relationBytes(id int64, keys, vals []uint32, rolesSID []int32, memIDs []int64, types []int32) []byte {
	body := pbVarintField(1, uint64(id))
	if len(keys) > 0 {
		body = append(body, pbPackedUint32(2, keys)...)
	}
	if len(vals) > 0 {
		body = append(body, pbPackedUint32(3, vals)...)
	}
	if len(rolesSID) > 0 {
		body = append(body, pbPackedInt32(8, rolesSID)...)
	}
	if len(memIDs) > 0 {
		body = append(body, pbPackedSint64(9, memIDs)...)
	}
	if len(types) > 0 {
		body = append(body, pbPackedInt32(10, types)...)
	}
	return body
}

// relationsGroup wraps each relation body as field 4 of a PrimitiveGroup.
func relationsGroup(rels ...[]byte) []byte {
	var group []byte
	for _, r := range rels {
		group = append(group, pbLenDelim(4, r)...)
	}
	return group
}

func TestRelationScannerNext(t *testing.T) {
	r1 := relationBytes(
		500,
		[]uint32{1}, []uint32{2},
		[]int32{3, 4},
		[]int64{100, -5, 10}, // → 100, 95, 105
		[]int32{osmbr.MemberTypeNode, osmbr.MemberTypeWay},
	)
	r2 := relationBytes(600, nil, nil, nil, nil, nil)

	block := primitiveBlockBytes([][]byte{nil}, pbLenDelim(2, relationsGroup(r1, r2))...)

	var (
		pb   osmbr.PrimitiveBlock
		rBuf osmbr.RelationBuf
	)
	if err := pb.DecodeFrom(block); err != nil {
		t.Fatalf("DecodeFrom: %v", err)
	}
	gs := pb.Groups()
	if !gs.Next() {
		t.Fatalf("Groups.Next: %v", gs.Err())
	}
	if gs.Type() != osmbr.GroupTypeRelations {
		t.Fatalf("Type = %v, want GroupTypeRelations", gs.Type())
	}

	rs := gs.RelationScanner()

	id1, ok := rs.Next(&rBuf, nil)
	if !ok {
		t.Fatalf("first Next: %v", rs.Err())
	}
	if id1 != 500 {
		t.Errorf("id = %d, want 500", id1)
	}
	if !slices.Equal(rBuf.Keys, []uint32{1}) {
		t.Errorf("Keys = %v", rBuf.Keys)
	}
	if !slices.Equal(rBuf.RolesSID, []int32{3, 4}) {
		t.Errorf("RolesSID = %v", rBuf.RolesSID)
	}
	if !slices.Equal(rBuf.MemIDs, []int64{100, 95, 105}) {
		t.Errorf("MemIDs = %v, want delta-decoded", rBuf.MemIDs)
	}
	if !slices.Equal(rBuf.Types, []int32{osmbr.MemberTypeNode, osmbr.MemberTypeWay}) {
		t.Errorf("Types = %v", rBuf.Types)
	}

	id2, ok := rs.Next(&rBuf, nil)
	if !ok {
		t.Fatalf("second Next: %v", rs.Err())
	}
	if id2 != 600 {
		t.Errorf("id = %d, want 600", id2)
	}
	if len(rBuf.Keys) != 0 || len(rBuf.MemIDs) != 0 {
		t.Errorf("expected empty slices on second relation")
	}

	if _, ok := rs.Next(&rBuf, nil); ok {
		t.Errorf("third Next returned ok, want end-of-iteration")
	}
	if err := rs.Err(); err != nil {
		t.Errorf("Err = %v, want nil", err)
	}
}

func TestRelationMemberConstants(t *testing.T) {
	// The constants map to wire-level int32 values 0/1/2 per PBF spec.
	if osmbr.MemberTypeNode != 0 {
		t.Errorf("MemberTypeNode = %d, want 0", osmbr.MemberTypeNode)
	}
	if osmbr.MemberTypeWay != 1 {
		t.Errorf("MemberTypeWay = %d, want 1", osmbr.MemberTypeWay)
	}
	if osmbr.MemberTypeRelation != 2 {
		t.Errorf("MemberTypeRelation = %d, want 2", osmbr.MemberTypeRelation)
	}
}
