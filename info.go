package osmbr

import "github.com/paulmach/protoscan"

// InfoBuf holds optional per-entity metadata decoded from an Info message.
// Pass a non-nil *InfoBuf to WayScanner.Next, RelationScanner.Next, or
// NodeScanner.Next to populate it; nil skips decoding entirely.
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

// decodeInfo decodes a serialized Info message into info.
func decodeInfo(data []byte, info *InfoBuf) error {
	*info = InfoBuf{}
	var msg protoscan.Message
	msg.Reset(data)
	for msg.Next() {
		var err error
		switch msg.FieldNumber() {
		case 1: // version (int32)
			info.Version, err = msg.Int32()
		case 2: // timestamp (int64)
			info.Timestamp, err = msg.Int64()
		case 3: // changeset (int64)
			info.Changeset, err = msg.Int64()
		case 4: // uid (int32)
			info.UID, err = msg.Int32()
		case 5: // user_sid (uint32)
			info.UserSID, err = msg.Uint32()
		case 6: // visible (bool)
			info.Visible, err = msg.Bool()
			if err == nil {
				info.HasVisible = true
			}
		default:
			msg.Skip()
		}
		if err != nil {
			return err
		}
	}
	return msg.Err()
}

// decodeDenseInfo decodes a serialized DenseInfo message into info.
// Resets all slices to [:0] then appends. Delta-decodes Timestamps, Changesets, UIDs.
func decodeDenseInfo(data []byte, info *DenseInfoBuf) error {
	info.Versions = info.Versions[:0]
	info.Timestamps = info.Timestamps[:0]
	info.Changesets = info.Changesets[:0]
	info.UIDs = info.UIDs[:0]
	info.UserSIDs = info.UserSIDs[:0]
	info.Visibles = info.Visibles[:0]

	var msg protoscan.Message
	msg.Reset(data)
	for msg.Next() {
		var err error
		switch msg.FieldNumber() {
		case 1: // version (packed int32, NOT delta)
			info.Versions, err = msg.RepeatedInt32(info.Versions)
		case 2: // timestamp (packed sint64, delta)
			info.Timestamps, err = msg.RepeatedSint64(info.Timestamps)
		case 3: // changeset (packed sint64, delta)
			info.Changesets, err = msg.RepeatedSint64(info.Changesets)
		case 4: // uid (packed sint32, delta)
			info.UIDs, err = msg.RepeatedSint32(info.UIDs)
		case 5: // user_sid (packed uint32, NOT delta)
			info.UserSIDs, err = msg.RepeatedUint32(info.UserSIDs)
		case 6: // visible (packed bool)
			info.Visibles, err = msg.RepeatedBool(info.Visibles)
		default:
			msg.Skip()
		}
		if err != nil {
			return err
		}
	}
	if err := msg.Err(); err != nil {
		return err
	}

	// Delta decode
	deltaDecodeInt64(info.Timestamps)
	deltaDecodeInt64(info.Changesets)
	deltaDecodeInt32(info.UIDs)
	return nil
}
