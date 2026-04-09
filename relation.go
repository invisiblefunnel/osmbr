package osmbr

import (
	"fmt"

	"github.com/paulmach/protoscan"
)

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
	msg protoscan.Message
	err error
}

// Next decodes the next Relation into buf and returns its ID.
// Resets buf slices to [:0] then appends (capacity preserved).
// Returns (0, false) when no more relations remain.
// Pass a non-nil info to also decode the Relation's Info; nil skips it.
func (rs *RelationScanner) Next(buf *RelationBuf, info *InfoBuf) (id int64, ok bool) {
	for rs.msg.Next() {
		if rs.msg.FieldNumber() != 4 { // repeated Relation
			rs.msg.Skip()
			continue
		}

		relData, err := rs.msg.MessageData()
		if err != nil {
			rs.err = fmt.Errorf("osmbr: Relation message: %w", err)
			return 0, false
		}

		buf.Keys = buf.Keys[:0]
		buf.Vals = buf.Vals[:0]
		buf.RolesSID = buf.RolesSID[:0]
		buf.MemIDs = buf.MemIDs[:0]
		buf.Types = buf.Types[:0]

		var relMsg protoscan.Message
		relMsg.Reset(relData)
		for relMsg.Next() {
			switch relMsg.FieldNumber() {
			case 1: // id (int64)
				id, err = relMsg.Int64()
			case 2: // keys (packed uint32)
				buf.Keys, err = relMsg.RepeatedUint32(buf.Keys)
			case 3: // vals (packed uint32)
				buf.Vals, err = relMsg.RepeatedUint32(buf.Vals)
			case 4: // info
				if info != nil {
					infoData, e := relMsg.MessageData()
					if e != nil {
						rs.err = fmt.Errorf("osmbr: Relation.info: %w", e)
						return 0, false
					}
					err = decodeInfo(infoData, info)
				} else {
					relMsg.Skip()
				}
			case 8: // roles_sid (packed int32)
				buf.RolesSID, err = relMsg.RepeatedInt32(buf.RolesSID)
			case 9: // memids (packed sint64, delta-encoded)
				buf.MemIDs, err = relMsg.RepeatedSint64(buf.MemIDs)
			case 10: // types (packed int32)
				buf.Types, err = relMsg.RepeatedInt32(buf.Types)
			default:
				relMsg.Skip()
			}
			if err != nil {
				rs.err = fmt.Errorf("osmbr: Relation field %d: %w", relMsg.FieldNumber(), err)
				return 0, false
			}
		}
		if err = relMsg.Err(); err != nil {
			rs.err = fmt.Errorf("osmbr: Relation: %w", err)
			return 0, false
		}

		deltaDecodeInt64(buf.MemIDs)
		return id, true
	}

	if err := rs.msg.Err(); err != nil {
		rs.err = err
	}
	return 0, false
}

// Err returns the first error encountered during iteration.
func (rs *RelationScanner) Err() error { return rs.err }
