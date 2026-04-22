package osmbr

import (
	"fmt"

	"github.com/paulmach/protoscan"
)

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
	msg protoscan.Message
	err error
}

// Next decodes the next Way into buf and returns its ID.
// Resets buf slices to [:0] then appends (capacity preserved).
// Returns (0, false) when no more ways remain.
// Pass a non-nil info to also decode the Way's Info; nil skips it.
func (ws *WayScanner) Next(buf *WayBuf, info *InfoBuf) (id int64, ok bool) {
	for ws.msg.Next() {
		if ws.msg.FieldNumber() != 3 { // repeated Way
			ws.msg.Skip()
			continue
		}

		wayData, err := ws.msg.MessageData()
		if err != nil {
			ws.err = fmt.Errorf("osmbr: Way message: %w", err)
			return 0, false
		}

		buf.Keys = buf.Keys[:0]
		buf.Vals = buf.Vals[:0]
		buf.Refs = buf.Refs[:0]

		var wayMsg protoscan.Message
		wayMsg.Reset(wayData)
		for wayMsg.Next() {
			switch wayMsg.FieldNumber() {
			case 1: // id (int64)
				id, err = wayMsg.Int64()
			case 2: // keys (packed uint32)
				buf.Keys, err = wayMsg.RepeatedUint32(buf.Keys)
			case 3: // vals (packed uint32)
				buf.Vals, err = wayMsg.RepeatedUint32(buf.Vals)
			case 4: // info
				if e := decodeOptionalInfo(&wayMsg, info, "Way"); e != nil {
					ws.err = e
					return 0, false
				}
			case 8: // refs (packed sint64, delta-encoded)
				buf.Refs, err = wayMsg.RepeatedSint64(buf.Refs)
			default:
				wayMsg.Skip()
			}
			if err != nil {
				ws.err = fmt.Errorf("osmbr: Way field %d: %w", wayMsg.FieldNumber(), err)
				return 0, false
			}
		}
		if err = wayMsg.Err(); err != nil {
			ws.err = fmt.Errorf("osmbr: Way: %w", err)
			return 0, false
		}

		deltaDecodeInt64(buf.Refs)
		return id, true
	}

	if err := ws.msg.Err(); err != nil {
		ws.err = fmt.Errorf("osmbr: PrimitiveGroup: %w", err)
	}
	return 0, false
}

// Err returns the first error encountered during iteration.
func (ws *WayScanner) Err() error { return ws.err }
