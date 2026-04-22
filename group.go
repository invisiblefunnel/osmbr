package osmbr

import (
	"fmt"

	"github.com/paulmach/protoscan"
)

// GroupType identifies the kind of entities in a PrimitiveGroup.
type GroupType int8

const (
	GroupTypeUnknown    GroupType = 0
	GroupTypeNodes      GroupType = 1
	GroupTypeDense      GroupType = 2
	GroupTypeWays       GroupType = 3
	GroupTypeRelations  GroupType = 4
	GroupTypeChangesets GroupType = 5
)

// GroupScanner iterates over PrimitiveGroups within a PrimitiveBlock.
// Obtain one via PrimitiveBlock.Groups. GroupScanner is a value type.
type GroupScanner struct {
	msg       protoscan.Message
	peek      protoscan.Message
	groupData []byte // raw bytes of current PrimitiveGroup (zero-copy)
	gType     GroupType
	err       error
}

// Next advances to the next PrimitiveGroup. Returns false on EOF or error.
// Call Err to distinguish between them.
func (gs *GroupScanner) Next() bool {
	for gs.msg.Next() {
		if gs.msg.FieldNumber() == 2 { // primitivegroup
			d, err := gs.msg.MessageData()
			if err != nil {
				gs.err = fmt.Errorf("osmbr: PrimitiveGroup message: %w", err)
				return false
			}
			gs.groupData = d

			// Peek at first field to identify group type
			gs.peek.Reset(d)
			gs.gType = GroupTypeUnknown
			if gs.peek.Next() {
				switch gs.peek.FieldNumber() {
				case 1:
					gs.gType = GroupTypeNodes
				case 2:
					gs.gType = GroupTypeDense
				case 3:
					gs.gType = GroupTypeWays
				case 4:
					gs.gType = GroupTypeRelations
				case 5:
					gs.gType = GroupTypeChangesets
				}
			}
			if err := gs.peek.Err(); err != nil {
				gs.err = fmt.Errorf("osmbr: PrimitiveGroup peek: %w", err)
				return false
			}
			return true
		}
		gs.msg.Skip()
	}
	if err := gs.msg.Err(); err != nil {
		gs.err = fmt.Errorf("osmbr: PrimitiveBlock: %w", err)
	}
	return false
}

// Type returns the GroupType of the current group.
func (gs *GroupScanner) Type() GroupType { return gs.gType }

// Err returns the first error encountered during iteration.
func (gs *GroupScanner) Err() error { return gs.err }

// DecodeDenseNodes decodes the current DenseNodes group into buf.
// Only valid when Type() == GroupTypeDense.
// Pass a non-nil info to also decode per-node metadata; nil skips it.
func (gs *GroupScanner) DecodeDenseNodes(buf *DenseNodesBuf, info *DenseInfoBuf) error {
	return DecodeDenseNodes(gs.groupData, buf, info)
}

// WayScanner returns a WayScanner for the current group.
// Only valid when Type() == GroupTypeWays.
func (gs *GroupScanner) WayScanner() WayScanner {
	var ws WayScanner
	ws.msg.Reset(gs.groupData)
	return ws
}

// RelationScanner returns a RelationScanner for the current group.
// Only valid when Type() == GroupTypeRelations.
func (gs *GroupScanner) RelationScanner() RelationScanner {
	var rs RelationScanner
	rs.msg.Reset(gs.groupData)
	return rs
}

// NodeScanner returns a NodeScanner for the current group.
// Only valid when Type() == GroupTypeNodes.
// Note: non-dense nodes are rare in practice; most OSM data uses DenseNodes.
func (gs *GroupScanner) NodeScanner() NodeScanner {
	var ns NodeScanner
	ns.msg.Reset(gs.groupData)
	return ns
}
