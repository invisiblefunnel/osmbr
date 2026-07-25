package osmbr

import "fmt"

// Member type constants for Relation members.
const (
	MemberTypeNode     = int32(0)
	MemberTypeWay      = int32(1)
	MemberTypeRelation = int32(2)
)

// RelationBuf is caller-managed memory for decoding Relation entities.
// Reuse across calls to avoid per-relation allocations.
// Keys, Vals, RolesSID, MemIDs, and Types are parallel arrays.
// MemIDs contains delta-decoded absolute member IDs.
type RelationBuf struct {
	Keys     []uint32 // string table indices for tag keys
	Vals     []uint32 // string table indices for tag values
	RolesSID []int32  // string table indices for member roles
	MemIDs   []int64  // delta-decoded absolute member IDs
	Types    []int32  // member types: MemberTypeNode, MemberTypeWay, MemberTypeRelation
}

// RelationScanner iterates over Relation messages in a PrimitiveGroup.
// Obtain one via GroupScanner.RelationScanner. RelationScanner is a value type.
type RelationScanner struct {
	m   msg
	err error
}

// Next decodes the next Relation into buf and returns its ID.
// Resets buf slices to [:0] then appends (capacity preserved).
// Returns (0, false) when no more relations remain.
// Pass a non-nil info to also decode the Relation's Info; nil skips it.
func (rs *RelationScanner) Next(buf *RelationBuf, info *InfoBuf) (id int64, ok bool) {
	for rs.m.next() {
		if rs.m.field != 4 { // repeated Relation
			rs.m.skip()
			continue
		}

		relData := rs.m.bytes()
		if rs.m.err != nil {
			rs.err = fmt.Errorf("osmbr: Relation message: %w", rs.m.err)
			return 0, false
		}

		buf.Keys = buf.Keys[:0]
		buf.Vals = buf.Vals[:0]
		buf.RolesSID = buf.RolesSID[:0]
		buf.MemIDs = buf.MemIDs[:0]
		buf.Types = buf.Types[:0]
		// See WayScanner.Next: info is optional per entity and must not carry
		// over from the previous Relation.
		if info != nil {
			*info = InfoBuf{}
		}

		var relMsg msg
		relMsg.reset(relData)
		for relMsg.next() {
			switch relMsg.field {
			case 1: // id (int64)
				id = relMsg.int64()
			case 2: // keys (packed uint32)
				buf.Keys = relMsg.repeatedUint32(buf.Keys)
			case 3: // vals (packed uint32)
				buf.Vals = relMsg.repeatedUint32(buf.Vals)
			case 4: // info
				decodeOptionalInfo(&relMsg, info)
			case 8: // roles_sid (packed int32)
				buf.RolesSID = relMsg.repeatedInt32(buf.RolesSID)
			case 9: // memids (packed sint64, delta-encoded)
				buf.MemIDs = relMsg.repeatedDeltaSint64(buf.MemIDs)
			case 10: // types (packed int32)
				buf.Types = relMsg.repeatedInt32(buf.Types)
			default:
				relMsg.skip()
			}
		}
		if relMsg.err != nil {
			rs.err = fmt.Errorf("osmbr: Relation: %w", relMsg.err)
			return 0, false
		}

		return id, true
	}

	if rs.m.err != nil {
		rs.err = fmt.Errorf("osmbr: PrimitiveGroup: %w", rs.m.err)
	}
	return 0, false
}

// Err returns the first error encountered during iteration.
func (rs *RelationScanner) Err() error { return rs.err }
