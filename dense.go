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
// The 0 value delimits one node's tags from the next. Example iteration:
//
//	j := 0
//	for i := range buf.IDs {
//	    for j < len(buf.KeysVals) && buf.KeysVals[j] != 0 {
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
		break // only one DenseNodes per PrimitiveGroup
	}
	if pgMsg.err != nil {
		return fmt.Errorf("osmbr: PrimitiveGroup: %w", pgMsg.err)
	}

	if len(buf.IDs) != len(buf.Lats) || len(buf.IDs) != len(buf.Lons) {
		return fmt.Errorf("osmbr: DenseNodes length mismatch: IDs=%d Lats=%d Lons=%d",
			len(buf.IDs), len(buf.Lats), len(buf.Lons))
	}

	return nil
}
