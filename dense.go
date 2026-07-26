package osmbr

import "fmt"

// DenseNodesBuf is caller-managed memory for decoding a DenseNodes group.
// Allocate once and reuse across blocks to avoid per-block allocations.
// After warm-up, all slices grow to accommodate the largest block seen and
// are then reused without further allocation.
//
// IDs, Lats, and Lons contain delta-decoded absolute values.
// To convert Lats[i] and Lons[i] to nanodegrees:
//
//	lat_nanodeg = Lats[i] * int64(pb.Granularity) + pb.LatOffset
//	lon_nanodeg = Lons[i] * int64(pb.Granularity) + pb.LonOffset
//
// KeysVals encodes tags as a flat array of string-table indices:
//
//	(keyIdx valIdx)* 0  per node, repeated
//
// The 0 value delimits one node's tags from the next. KeysVals is not
// validated: a malformed file may end mid-pair, and the indices themselves are
// not checked against the string table, so bound the pair read and use
// NumStrings before calling String. Example iteration:
//
//	j := 0
//	for i := range buf.IDs {
//	    // j+1 keeps a trailing key with no value from reading past the end.
//	    for j+1 < len(buf.KeysVals) && buf.KeysVals[j] != 0 {
//	        key := pb.String(int(buf.KeysVals[j]))
//	        val := pb.String(int(buf.KeysVals[j+1]))
//	        j += 2
//	    }
//	    j++ // skip the 0 delimiter
//	}
type DenseNodesBuf struct {
	IDs      []int64
	Lats     []int64
	Lons     []int64
	KeysVals []int32
}

// DecodeDenseNodes decodes a DenseNodes PrimitiveGroup into buf.
// groupData is the raw bytes of a PrimitiveGroup message (from GroupScanner.groupData).
// Resets all slices to [:0] then appends. Delta-decodes IDs, Lats, Lons.
// Pass a non-nil info to also decode DenseInfo metadata; nil skips it.
func DecodeDenseNodes(groupData []byte, buf *DenseNodesBuf, info *DenseInfoBuf) error {
	buf.IDs = buf.IDs[:0]
	buf.Lats = buf.Lats[:0]
	buf.Lons = buf.Lons[:0]
	buf.KeysVals = buf.KeysVals[:0]

	// Reset up front, not in decodeDenseInfo: denseinfo is an optional field, so
	// a group that omits it would otherwise leave the previous group's metadata
	// in place for the caller to read against this group's nodes.
	if info != nil {
		info.reset()
	}

	// Scan PrimitiveGroup for field 2 (DenseNodes message)
	var pgMsg msg
	pgMsg.reset(groupData)
	for pgMsg.next() {
		if pgMsg.field != 2 {
			pgMsg.skip()
			continue
		}

		denseData := pgMsg.bytes()
		if pgMsg.err != nil {
			return fmt.Errorf("osmbr: DenseNodes message: %w", pgMsg.err)
		}

		var dnMsg msg
		dnMsg.reset(denseData)
		for dnMsg.next() {
			switch dnMsg.field {
			case 1: // id (packed sint64, delta-encoded)
				buf.IDs = dnMsg.repeatedDeltaSint64(buf.IDs)
			case 8: // lat (packed sint64, delta-encoded)
				buf.Lats = dnMsg.repeatedDeltaSint64(buf.Lats)
			case 9: // lon (packed sint64, delta-encoded)
				buf.Lons = dnMsg.repeatedDeltaSint64(buf.Lons)
			case 10: // keys_vals (packed int32)
				buf.KeysVals = dnMsg.repeatedInt32(buf.KeysVals)
			case 5: // denseinfo
				if info == nil {
					dnMsg.skip()
					break
				}
				infoData := dnMsg.bytes()
				if dnMsg.err != nil {
					return fmt.Errorf("osmbr: DenseInfo message: %w", dnMsg.err)
				}
				if err := decodeDenseInfo(infoData, info); err != nil {
					return fmt.Errorf("osmbr: DenseInfo: %w", err)
				}
			default:
				dnMsg.skip()
			}
		}
		if dnMsg.err != nil {
			return fmt.Errorf("osmbr: DenseNodes: %w", dnMsg.err)
		}
		// A group carries at most one DenseNodes, but the scan continues rather
		// than stopping here. Stopping would leave the rest of the group
		// unvalidated, so a file damaged past this point would decode as
		// though it were intact; and protobuf merges a singular message field
		// that appears more than once, which for these arrays means appending
		// with the delta totals carried across — which is what the repeated
		// decoders already do for a field split over several wire entries.
	}
	if pgMsg.err != nil {
		return fmt.Errorf("osmbr: PrimitiveGroup: %w", pgMsg.err)
	}

	if len(buf.IDs) != len(buf.Lats) || len(buf.IDs) != len(buf.Lons) {
		return fmt.Errorf("osmbr: DenseNodes length mismatch: IDs=%d Lats=%d Lons=%d",
			len(buf.IDs), len(buf.Lats), len(buf.Lons))
	}
	if info != nil {
		if err := checkDenseInfoLen(info, len(buf.IDs)); err != nil {
			return err
		}
	}

	return nil
}

// checkDenseInfoLen reports whether every DenseInfo array is either absent or
// exactly as long as the node arrays it parallels. Callers index these by node
// position, so a short array from a malformed file would otherwise panic at the
// call site instead of failing here.
//
// Absent (length 0) is allowed throughout: a file carries metadata for every
// node in a group or none, and visible in particular only appears in
// full-history extracts.
func checkDenseInfoLen(info *DenseInfoBuf, n int) error {
	if got := len(info.Versions); got != 0 && got != n {
		return denseInfoLenErr("version", got, n)
	}
	if got := len(info.Timestamps); got != 0 && got != n {
		return denseInfoLenErr("timestamp", got, n)
	}
	if got := len(info.Changesets); got != 0 && got != n {
		return denseInfoLenErr("changeset", got, n)
	}
	if got := len(info.UIDs); got != 0 && got != n {
		return denseInfoLenErr("uid", got, n)
	}
	if got := len(info.UserSIDs); got != 0 && got != n {
		return denseInfoLenErr("user_sid", got, n)
	}
	if got := len(info.Visibles); got != 0 && got != n {
		return denseInfoLenErr("visible", got, n)
	}
	return nil
}

// denseInfoLenErr keeps the formatting off checkDenseInfoLen's hot path.
func denseInfoLenErr(field string, got, want int) error {
	return fmt.Errorf("osmbr: DenseInfo.%s length mismatch: %d entries, want %d or 0",
		field, got, want)
}
