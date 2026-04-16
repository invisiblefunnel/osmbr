package osmbr

import (
	"fmt"

	"github.com/paulmach/protoscan"
)

// PrimitiveBlock holds the decoded metadata and string table for an OSMData block.
// Call DecodeFrom to populate from BlockReader.Data(). Call Groups to iterate groups.
//
// String table entries are zero-copy slices into the data passed to DecodeFrom.
// They are only valid until the next call to DecodeFrom or BlockReader.Next.
type PrimitiveBlock struct {
	// Granularity is the coordinate granularity in nanodegrees (default 100).
	// To convert a raw lat/lon integer to nanodegrees:
	//
	//   lat_nanodeg = Lats[i] * int64(Granularity) + LatOffset
	//   lon_nanodeg = Lons[i] * int64(Granularity) + LonOffset
	Granularity int32
	// LatOffset is the latitude offset in nanodegrees (default 0).
	LatOffset int64
	// LonOffset is the longitude offset in nanodegrees (default 0).
	LonOffset int64
	// DateGranularity is the timestamp granularity in milliseconds (default 1000).
	DateGranularity int32

	strings [][]byte // zero-copy slices into the data passed to DecodeFrom
	data    []byte   // retained for re-scanning groups
}

// DecodeFrom populates the PrimitiveBlock from raw OSMData block bytes.
// data is the value returned by BlockReader.Data().
//
// String table entries reference data's memory. Copy entries you need to
// retain past the next BlockReader.Next call.
func (pb *PrimitiveBlock) DecodeFrom(data []byte) error {
	// Reset to defaults
	pb.Granularity = 100
	pb.LatOffset = 0
	pb.LonOffset = 0
	pb.DateGranularity = 1000
	pb.strings = pb.strings[:0]
	pb.data = data

	var msg protoscan.Message
	msg.Reset(data)
	for msg.Next() {
		switch msg.FieldNumber() {
		case 1: // stringtable
			stData, err := msg.MessageData()
			if err != nil {
				return fmt.Errorf("osmbr: PrimitiveBlock.stringtable: %w", err)
			}
			var stMsg protoscan.Message
			stMsg.Reset(stData)
			for stMsg.Next() {
				if stMsg.FieldNumber() == 1 {
					b, err := stMsg.Bytes()
					if err != nil {
						return fmt.Errorf("osmbr: StringTable.s: %w", err)
					}
					pb.strings = append(pb.strings, b)
				} else {
					stMsg.Skip()
				}
			}
			if err := stMsg.Err(); err != nil {
				return fmt.Errorf("osmbr: StringTable: %w", err)
			}
		case 2: // primitivegroup — deferred; re-scanned by Groups()
			msg.Skip()
		case 17: // granularity
			v, err := msg.Int32()
			if err != nil {
				return fmt.Errorf("osmbr: PrimitiveBlock.granularity: %w", err)
			}
			pb.Granularity = v
		case 18: // date_granularity
			v, err := msg.Int32()
			if err != nil {
				return fmt.Errorf("osmbr: PrimitiveBlock.date_granularity: %w", err)
			}
			pb.DateGranularity = v
		case 19: // lat_offset
			v, err := msg.Int64()
			if err != nil {
				return fmt.Errorf("osmbr: PrimitiveBlock.lat_offset: %w", err)
			}
			pb.LatOffset = v
		case 20: // lon_offset
			v, err := msg.Int64()
			if err != nil {
				return fmt.Errorf("osmbr: PrimitiveBlock.lon_offset: %w", err)
			}
			pb.LonOffset = v
		default:
			msg.Skip()
		}
	}
	if err := msg.Err(); err != nil {
		return fmt.Errorf("osmbr: PrimitiveBlock: %w", err)
	}
	return nil
}

// String returns the string table entry at index i.
// The returned slice is a zero-copy reference into the block data.
// Copy it if you need to retain it past the next BlockReader.Next call.
func (pb *PrimitiveBlock) String(i int) []byte { return pb.strings[i] }

// NumStrings returns the number of entries in the string table.
func (pb *PrimitiveBlock) NumStrings() int { return len(pb.strings) }

// Groups returns a GroupScanner for iterating over the PrimitiveGroups
// in this block. The scanner re-reads from the original block data.
func (pb *PrimitiveBlock) Groups() GroupScanner {
	var gs GroupScanner
	gs.msg.Reset(pb.data)
	return gs
}
