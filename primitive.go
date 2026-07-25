package osmbr

import "fmt"

// PrimitiveBlock holds the decoded metadata and string table for an OSMData block.
// Call DecodeFrom to populate from a Decompressor's output. Call Groups to iterate groups.
//
// String table entries are zero-copy slices into the data passed to DecodeFrom.
// They are only valid until the next call to DecodeFrom on this block or to
// Decompressor.Decompress on the underlying decompressor (which reuses its buffer).
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

// DecodeFrom populates the PrimitiveBlock from decompressed OSMData block bytes
// (typically the result of Decompressor.Decompress).
//
// String table entries reference data's memory. Copy entries you need to
// retain past the next Decompressor.Decompress or DecodeFrom call.
func (pb *PrimitiveBlock) DecodeFrom(data []byte) error {
	// Reset to defaults
	pb.Granularity = 100
	pb.LatOffset = 0
	pb.LonOffset = 0
	pb.DateGranularity = 1000
	pb.strings = pb.strings[:0]
	pb.data = data

	var m msg
	m.reset(data)
	for m.next() {
		switch m.field {
		case 1: // stringtable
			stData := m.bytes()
			if m.err != nil {
				return fmt.Errorf("osmbr: PrimitiveBlock.stringtable: %w", m.err)
			}
			var stMsg msg
			stMsg.reset(stData)
			for stMsg.next() {
				if stMsg.field == 1 {
					pb.strings = append(pb.strings, stMsg.bytes())
				} else {
					stMsg.skip()
				}
			}
			if stMsg.err != nil {
				return fmt.Errorf("osmbr: StringTable: %w", stMsg.err)
			}
		case 2: // primitivegroup — deferred; re-scanned by Groups()
			m.skip()
		case 17: // granularity
			pb.Granularity = m.int32()
		case 18: // date_granularity
			pb.DateGranularity = m.int32()
		case 19: // lat_offset
			pb.LatOffset = m.int64()
		case 20: // lon_offset
			pb.LonOffset = m.int64()
		default:
			m.skip()
		}
	}
	if m.err != nil {
		return fmt.Errorf("osmbr: PrimitiveBlock: %w", m.err)
	}
	return nil
}

// String returns the string table entry at index i.
// The returned slice is a zero-copy reference into the block data and is only
// valid until the next call to DecodeFrom or Decompressor.Decompress.
// Panics if i is out of range.
func (pb *PrimitiveBlock) String(i int) []byte { return pb.strings[i] }

// NumStrings returns the number of entries in the string table.
func (pb *PrimitiveBlock) NumStrings() int { return len(pb.strings) }

// Groups returns a GroupScanner for iterating over the PrimitiveGroups
// in this block. The scanner re-reads from the original block data.
func (pb *PrimitiveBlock) Groups() GroupScanner {
	var gs GroupScanner
	gs.m.reset(pb.data)
	return gs
}
