package osmbr

import "fmt"

// WayBuf is caller-managed memory for decoding Way entities.
// Reuse across calls to avoid per-way allocations.
// After DecodeWay, Keys and Vals are parallel string-table index arrays.
// Refs contains delta-decoded absolute node IDs.
type WayBuf struct {
	Keys []uint32 // string table indices for tag keys
	Vals []uint32 // string table indices for tag values
	Refs []int64  // delta-decoded absolute referenced node IDs
}

// WayScanner iterates over Way messages in a PrimitiveGroup.
// Obtain one via GroupScanner.WayScanner. WayScanner is a value type.
type WayScanner struct {
	m   msg
	err error
}

// Next decodes the next Way into buf and returns its ID.
// Resets buf slices to [:0] then appends (capacity preserved).
// Returns (0, false) when no more ways remain.
// Pass a non-nil info to also decode the Way's Info; nil skips it.
func (ws *WayScanner) Next(buf *WayBuf, info *InfoBuf) (id int64, ok bool) {
	for ws.m.next() {
		if ws.m.field != 3 { // repeated Way
			ws.m.skip()
			continue
		}

		wayData := ws.m.bytes()
		if ws.m.err != nil {
			ws.err = fmt.Errorf("osmbr: Way message: %w", ws.m.err)
			return 0, false
		}

		buf.Keys = buf.Keys[:0]
		buf.Vals = buf.Vals[:0]
		buf.Refs = buf.Refs[:0]

		var wayMsg msg
		wayMsg.reset(wayData)
		for wayMsg.next() {
			switch wayMsg.field {
			case 1: // id (int64)
				id = wayMsg.int64()
			case 2: // keys (packed uint32)
				buf.Keys = wayMsg.repeatedUint32(buf.Keys)
			case 3: // vals (packed uint32)
				buf.Vals = wayMsg.repeatedUint32(buf.Vals)
			case 4: // info
				decodeOptionalInfo(&wayMsg, info, "Way")
			case 8: // refs (packed sint64, delta-encoded)
				buf.Refs = wayMsg.repeatedDeltaSint64(buf.Refs)
			default:
				wayMsg.skip()
			}
		}
		if wayMsg.err != nil {
			ws.err = fmt.Errorf("osmbr: Way: %w", wayMsg.err)
			return 0, false
		}

		return id, true
	}

	if ws.m.err != nil {
		ws.err = fmt.Errorf("osmbr: PrimitiveGroup: %w", ws.m.err)
	}
	return 0, false
}

// Err returns the first error encountered during iteration.
func (ws *WayScanner) Err() error { return ws.err }
