package osmbr

import "fmt"

// InfoBuf holds optional per-entity metadata decoded from an Info message.
// Pass a non-nil *InfoBuf to WayScanner.Next, RelationScanner.Next, or
// NodeScanner.Next to populate it; nil skips decoding entirely.
//
// Each Next zeroes the buffer before decoding, so one InfoBuf can be reused
// across a whole file: an entity carrying no Info reads back as the zero
// value rather than as the previous entity's metadata.
type InfoBuf struct {
	Version    int32
	Timestamp  int64 // milliseconds since Unix epoch
	Changeset  int64
	UID        int32
	UserSID    uint32 // index into the block's string table
	Visible    bool
	HasVisible bool // false if the visible field was absent
}

// DenseInfoBuf holds optional per-node metadata arrays decoded from a DenseInfo
// message. All slices are grown as needed (capacity preserved across calls).
// Pass a non-nil *DenseInfoBuf to DecodeDenseNodes to populate; nil skips it.
//
// DecodeDenseNodes guarantees every array here is either empty or exactly as
// long as DenseNodesBuf.IDs, so an array that is non-empty can be indexed by
// node position without a bounds check of its own. A file that violates this
// is rejected rather than decoded. An array is empty whenever the group omits
// that field — including when the group carries no DenseInfo at all, which
// clears anything a previous group left behind.
//
// Delta-decoded fields: Timestamps, Changesets, UIDs.
// Non-delta fields: Versions, UserSIDs.
type DenseInfoBuf struct {
	Versions   []int32
	Timestamps []int64  // delta-decoded; milliseconds since Unix epoch
	Changesets []int64  // delta-decoded
	UIDs       []int32  // delta-decoded
	UserSIDs   []uint32 // indices into the block's string table
	Visibles   []bool
}

// decodeOptionalInfo decodes the current field of m as an Info submessage
// into *info. If info is nil, the field is skipped. Failures are recorded on
// m, whose caller wraps them with the enclosing entity name.
func decodeOptionalInfo(m *msg, info *InfoBuf) {
	if info == nil {
		m.skip()
		return
	}
	data := m.bytes()
	if m.err != nil {
		return
	}
	if err := decodeInfo(data, info); err != nil {
		m.fail(fmt.Errorf("info: %w", err))
	}
}

// decodeInfo decodes a serialized Info message into info, which the scanner
// has already zeroed. Every Info field is optional, so an absent one leaves
// the zero value.
func decodeInfo(data []byte, info *InfoBuf) error {
	var m msg
	m.reset(data)
	for m.next() {
		switch m.field {
		case 1: // version (int32)
			info.Version = m.int32()
		case 2: // timestamp (int64)
			info.Timestamp = m.int64()
		case 3: // changeset (int64)
			info.Changeset = m.int64()
		case 4: // uid (int32)
			info.UID = m.int32()
		case 5: // user_sid (uint32)
			info.UserSID = m.uint32()
		case 6: // visible (bool)
			info.Visible = m.boolean()
			info.HasVisible = m.err == nil
		default:
			m.skip()
		}
	}
	return m.err
}

// reset truncates every array, preserving capacity.
func (info *DenseInfoBuf) reset() {
	info.Versions = info.Versions[:0]
	info.Timestamps = info.Timestamps[:0]
	info.Changesets = info.Changesets[:0]
	info.UIDs = info.UIDs[:0]
	info.UserSIDs = info.UserSIDs[:0]
	info.Visibles = info.Visibles[:0]
}

// decodeDenseInfo decodes a serialized DenseInfo message into info, appending
// to arrays that DecodeDenseNodes has already reset. Delta-decodes Timestamps,
// Changesets, UIDs.
func decodeDenseInfo(data []byte, info *DenseInfoBuf) error {
	var m msg
	m.reset(data)
	for m.next() {
		switch m.field {
		case 1: // version (packed int32, NOT delta)
			info.Versions = m.repeatedInt32(info.Versions)
		case 2: // timestamp (packed sint64, delta)
			info.Timestamps = m.repeatedDeltaSint64(info.Timestamps)
		case 3: // changeset (packed sint64, delta)
			info.Changesets = m.repeatedDeltaSint64(info.Changesets)
		case 4: // uid (packed sint32, delta)
			info.UIDs = m.repeatedDeltaSint32(info.UIDs)
		case 5: // user_sid (packed uint32, NOT delta)
			info.UserSIDs = m.repeatedUint32(info.UserSIDs)
		case 6: // visible (packed bool)
			info.Visibles = m.repeatedBool(info.Visibles)
		default:
			m.skip()
		}
	}
	return m.err
}
