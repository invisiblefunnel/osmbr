package osmbr

import (
	"fmt"

	"github.com/paulmach/protoscan"
)

// NodeBuf is caller-managed memory for decoding individual Node entities.
// Non-dense nodes are rare in practice; most OSM data uses DenseNodes.
// Reuse across calls to avoid per-node allocations.
type NodeBuf struct {
	Keys []uint32 // string table indices for tag keys
	Vals []uint32 // string table indices for tag values
}

// NodeScanner iterates over individual Node messages in a PrimitiveGroup.
// Obtain one via GroupScanner.NodeScanner. NodeScanner is a value type.
// Note: in practice, OSM planet files and extracts use DenseNodes exclusively.
type NodeScanner struct {
	msg protoscan.Message
	err error
}

// Next decodes the next Node into buf and returns its ID, lat, and lon.
// Resets buf slices to [:0] then appends (capacity preserved).
// Returns (0, 0, 0, false) when no more nodes remain.
// lat and lon are raw sint64 values. Convert to nanodegrees:
//
//	lat_nanodeg = lat * int64(pb.Granularity) + pb.LatOffset
//
// Pass a non-nil info to also decode the Node's Info; nil skips it.
func (ns *NodeScanner) Next(buf *NodeBuf, info *InfoBuf) (id, lat, lon int64, ok bool) {
	for ns.msg.Next() {
		if ns.msg.FieldNumber() != 1 { // repeated Node
			ns.msg.Skip()
			continue
		}

		nodeData, err := ns.msg.MessageData()
		if err != nil {
			ns.err = fmt.Errorf("osmbr: Node message: %w", err)
			return 0, 0, 0, false
		}

		buf.Keys = buf.Keys[:0]
		buf.Vals = buf.Vals[:0]
		id, lat, lon = 0, 0, 0

		var nodeMsg protoscan.Message
		nodeMsg.Reset(nodeData)
		for nodeMsg.Next() {
			switch nodeMsg.FieldNumber() {
			case 1: // id (sint64)
				id, err = nodeMsg.Sint64()
			case 2: // keys (packed uint32)
				buf.Keys, err = nodeMsg.RepeatedUint32(buf.Keys)
			case 3: // vals (packed uint32)
				buf.Vals, err = nodeMsg.RepeatedUint32(buf.Vals)
			case 4: // info
				if e := decodeOptionalInfo(&nodeMsg, info, "Node"); e != nil {
					ns.err = e
					return 0, 0, 0, false
				}
			case 8: // lat (sint64)
				lat, err = nodeMsg.Sint64()
			case 9: // lon (sint64)
				lon, err = nodeMsg.Sint64()
			default:
				nodeMsg.Skip()
			}
			if err != nil {
				ns.err = fmt.Errorf("osmbr: Node field %d: %w", nodeMsg.FieldNumber(), err)
				return 0, 0, 0, false
			}
		}
		if err = nodeMsg.Err(); err != nil {
			ns.err = fmt.Errorf("osmbr: Node: %w", err)
			return 0, 0, 0, false
		}

		return id, lat, lon, true
	}

	if err := ns.msg.Err(); err != nil {
		ns.err = fmt.Errorf("osmbr: PrimitiveGroup: %w", err)
	}
	return 0, 0, 0, false
}

// Err returns the first error encountered during iteration.
func (ns *NodeScanner) Err() error { return ns.err }
