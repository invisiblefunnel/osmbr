package osmbr

import "fmt"

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
	m   msg
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
	for ns.m.next() {
		if ns.m.field != 1 { // repeated Node
			ns.m.skip()
			continue
		}

		nodeData := ns.m.bytes()
		if ns.m.err != nil {
			ns.err = fmt.Errorf("osmbr: Node message: %w", ns.m.err)
			return 0, 0, 0, false
		}

		buf.Keys = buf.Keys[:0]
		buf.Vals = buf.Vals[:0]
		id, lat, lon = 0, 0, 0
		// See WayScanner.Next: info is optional per entity and must not carry
		// over from the previous Node.
		if info != nil {
			*info = InfoBuf{}
		}

		var nodeMsg msg
		nodeMsg.reset(nodeData)
		for nodeMsg.next() {
			switch nodeMsg.field {
			case 1: // id (sint64)
				id = nodeMsg.sint64()
			case 2: // keys (packed uint32)
				buf.Keys = nodeMsg.repeatedUint32(buf.Keys)
			case 3: // vals (packed uint32)
				buf.Vals = nodeMsg.repeatedUint32(buf.Vals)
			case 4: // info
				decodeOptionalInfo(&nodeMsg, info)
			case 8: // lat (sint64)
				lat = nodeMsg.sint64()
			case 9: // lon (sint64)
				lon = nodeMsg.sint64()
			default:
				nodeMsg.skip()
			}
		}
		if nodeMsg.err != nil {
			ns.err = fmt.Errorf("osmbr: Node: %w", nodeMsg.err)
			return 0, 0, 0, false
		}

		return id, lat, lon, true
	}

	if ns.m.err != nil {
		ns.err = fmt.Errorf("osmbr: PrimitiveGroup: %w", ns.m.err)
	}
	return 0, 0, 0, false
}

// Err returns the first error encountered during iteration.
func (ns *NodeScanner) Err() error { return ns.err }
