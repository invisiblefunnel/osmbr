package osmbr_test

// A reference PBF decoder, used as the oracle for the differential tests in
// differential_test.go and the fuzz targets in fuzz_test.go.
//
// Everything here is written for obviousness, not speed: one value per loop
// iteration, no unrolling, no buffer reuse, no fused passes, freely allocating.
// It exists to be read and agreed with by eye. If a change to the optimized
// decoder in the package under test makes a differential test fail, the
// presumption is that the optimized decoder is wrong.
//
// Where the reference is deliberately strict, or deliberately lax, the rule is
// stated at the point it is applied and attributed to one of:
//
//   - protobuf: the encoding spec at https://protobuf.dev/programming-guides/encoding/
//     and the behaviour of google.golang.org/protobuf, which the scalar
//     conversions in refScalars were checked against value by value.
//   - PBF: the OSM PBF format at https://wiki.openstreetmap.org/wiki/PBF_Format
//     and the osmformat.proto/fileformat.proto schemas.
//   - osmbr: a documented choice by the package under test that is stricter
//     than protobuf requires. These are the only places the reference encodes a
//     decision rather than a spec, and each says why.

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

// Protobuf wire types.
const (
	refWireVarint  = 0
	refWireFixed64 = 1
	refWireBytes   = 2
	refWireFixed32 = 5
)

// PBF format limits, mirroring the constants in block.go.
const (
	refMaxBlobHeaderSize = 64 * 1024
	refMaxBlobSize       = 32 * 1024 * 1024
)

// refMaxFieldNumber is the largest field number protobuf permits (2^29-1).
//
// protobuf: field numbers above this are invalid. google.golang.org/protobuf is
// laxer here — protowire.DecodeTag accepts anything up to MaxInt32 — but the
// spec is unambiguous and osmbr enforces it, so the reference does too.
const refMaxFieldNumber = 1<<29 - 1

var (
	errRefVarint   = errors.New("ref: malformed varint")
	errRefTruncate = errors.New("ref: truncated field")
	errRefField    = errors.New("ref: field number out of range")
	errRefWireType = errors.New("ref: unsupported wire type")
)

// refVarint decodes the varint starting at data[i], returning its value and the
// index just past it.
//
// protobuf: a varint is at most ten bytes, and the tenth carries only one
// meaningful bit, so a tenth byte above 1 overflows uint64. This matches
// protowire.ConsumeVarint, which stops at ten bytes and rejects b[9] > 1.
func refVarint(data []byte, i int) (v uint64, next int, err error) {
	for n := 0; n < 10; n++ {
		if i >= len(data) {
			return 0, 0, errRefVarint // truncated
		}
		c := data[i]
		i++
		if n == 9 && c > 1 {
			return 0, 0, errRefVarint // overflows uint64
		}
		v |= uint64(c&0x7f) << (7 * n)
		if c < 0x80 {
			return v, i, nil
		}
	}
	return 0, 0, errRefVarint // no terminating byte within ten
}

// refField is one field read off the wire.
type refField struct {
	num int32
	typ uint8
	val uint64 // varint, fixed32, or fixed64 value
	buf []byte // length-delimited payload, a subslice of the message
}

// refScanner walks a protobuf message field by field.
//
// It reads each field's value eagerly, unlike the package under test, whose
// accessors read the value only when the caller asks for it. The difference is
// invisible to a caller that decodes every field it meets and checks for an
// error before using any result, which is what both decoders do; it shows up
// only in what a decoder has half-written when it reports a failure, and the
// differential oracle compares decoded values only when neither side failed.
type refScanner struct {
	data []byte
	i    int
}

// next reads the next field. It reports ok=false at the end of the message and
// on the first error, after which it must not be called again.
func (s *refScanner) next() (f refField, ok bool, err error) {
	if s.i >= len(s.data) {
		return f, false, nil
	}
	tag, next, err := refVarint(s.data, s.i)
	if err != nil {
		return f, false, err
	}
	s.i = next

	num := tag >> 3
	// protobuf: field number 0 is invalid, in the single-byte form and in the
	// non-canonical multi-byte forms (0x80 0x00 and friends) alike.
	if num == 0 || num > refMaxFieldNumber {
		return f, false, errRefField
	}
	f.num = int32(num)
	f.typ = uint8(tag & 7)

	switch f.typ {
	case refWireVarint:
		f.val, s.i, err = refVarint(s.data, s.i)
		if err != nil {
			return refField{}, false, err
		}
	case refWireFixed64:
		if len(s.data)-s.i < 8 {
			return refField{}, false, errRefTruncate
		}
		f.val = binary.LittleEndian.Uint64(s.data[s.i:])
		s.i += 8
	case refWireBytes:
		n, next, err := refVarint(s.data, s.i)
		if err != nil {
			return refField{}, false, err
		}
		if n > uint64(len(s.data)-next) {
			return refField{}, false, errRefTruncate
		}
		f.buf = s.data[next : next+int(n)]
		s.i = next + int(n)
	case refWireFixed32:
		if len(s.data)-s.i < 4 {
			return refField{}, false, errRefTruncate
		}
		f.val = uint64(binary.LittleEndian.Uint32(s.data[s.i:]))
		s.i += 4
	default:
		// Wire types 3 and 4 are protobuf's deprecated groups; 6 and 7 have
		// never been assigned.
		//
		// osmbr: groups are rejected rather than skipped. No PBF message uses
		// them, and a decoder that cannot descend into one cannot honestly
		// claim to have validated a message containing one.
		return refField{}, false, errRefWireType
	}
	return f, true, nil
}

// refTagOnly reads just the tag of the first field of a message, which is all
// GroupScanner looks at to classify a PrimitiveGroup. It reports ok=false for
// an empty message.
//
// Reading no further is what makes a group whose first field has a valid tag
// but an invalid wire type classifiable rather than an error.
func refTagOnly(data []byte) (num int32, ok bool, err error) {
	if len(data) == 0 {
		return 0, false, nil
	}
	tag, _, err := refVarint(data, 0)
	if err != nil {
		return 0, false, err
	}
	n := tag >> 3
	if n == 0 || n > refMaxFieldNumber {
		return 0, false, errRefField
	}
	return int32(n), true, nil
}

// --- scalar conversions -----------------------------------------------------
//
// refScalars in differential_test.go checks each of these against
// google.golang.org/protobuf over an exhaustive edge-case corpus.

func refInt32(v uint64) int32   { return int32(v) }
func refInt64(v uint64) int64   { return int64(v) }
func refUint32(v uint64) uint32 { return uint32(v) }
func refBool(v uint64) bool     { return v != 0 }

// refSint64 reverses zigzag encoding.
func refSint64(v uint64) int64 { return int64(v>>1) ^ -int64(v&1) }

// refSint32 reverses zigzag encoding for a 32-bit field.
//
// protobuf: the varint is masked to 32 bits and only then zigzag-decoded, so
// the sign bit of the result comes from bit 31 of the encoded value. Decoding
// all 64 bits and truncating afterwards is not the same thing: it takes the
// sign from bit 63 and lets bit 32 land on the result's sign bit. The two agree
// on every value a sint32 can legitimately encode and disagree as soon as bit
// 32 is set. Cross-checked against
// int32(protowire.DecodeZigZag(v & math.MaxUint32)).
func refSint32(v uint64) int32 { return int32(refSint64(v & math.MaxUint32)) }

// --- repeated fields -------------------------------------------------------

// refVarints returns the raw varint values carried by one wire entry of a
// repeated scalar field, accepting both encodings: packed, where a single
// length-delimited field holds every value, and unpacked, where each value is
// its own varint field.
//
// protobuf: a decoder must accept either encoding for a repeated scalar field
// whichever the schema declares, and the two may be mixed within one message.
//
// A truncated packed payload yields the values that preceded the damage along
// with the error, matching what the package under test leaves in the caller's
// buffer.
func refVarints(f refField) ([]uint64, error) {
	switch f.typ {
	case refWireVarint:
		return []uint64{f.val}, nil
	case refWireBytes:
		var out []uint64
		for i := 0; i < len(f.buf); {
			v, next, err := refVarint(f.buf, i)
			if err != nil {
				return out, err
			}
			out = append(out, v)
			i = next
		}
		return out, nil
	default:
		return nil, errRefWireType
	}
}

// refDeltaSint64 delta-decodes zigzag values, continuing from prev. PBF
// delta-coded fields accumulate across every wire entry of the field, so a
// field split into several entries picks up where the previous one left off.
func refDeltaSint64(prev int64, vals []uint64) (int64, []int64) {
	out := make([]int64, 0, len(vals))
	for _, v := range vals {
		prev += refSint64(v)
		out = append(out, prev)
	}
	return prev, out
}

// refDeltaSint32 is refDeltaSint64 for sint32 fields. The running total is
// 32-bit, so it wraps where the 64-bit one would not.
func refDeltaSint32(prev int32, vals []uint64) (int32, []int32) {
	out := make([]int32, 0, len(vals))
	for _, v := range vals {
		prev += refSint32(v)
		out = append(out, prev)
	}
	return prev, out
}

// --- BlobHeader framing ----------------------------------------------------

// refBlock is one FileBlock: a BlobHeader's type and the raw Blob that follows.
type refBlock struct {
	Type   string
	Offset int64
	Blob   []byte
}

// refBlocks splits a PBF byte stream into FileBlocks. It returns the blocks
// read before any failure, so a caller can compare a prefix.
//
// PBF: each block is a big-endian uint32 giving the BlobHeader's length, that
// BlobHeader, and then BlobHeader.datasize bytes of Blob.
func refBlocks(data []byte) ([]refBlock, error) {
	var out []refBlock
	pos := 0
	for {
		// A stream may end only on a block boundary. Fewer than four bytes
		// left, but more than none, is a file truncated mid-block, not a file
		// that ended.
		if pos == len(data) {
			return out, nil
		}
		if len(data)-pos < 4 {
			return out, fmt.Errorf("ref: truncated BlobHeader length")
		}
		offset := int64(pos)
		headerLen := binary.BigEndian.Uint32(data[pos:])
		pos += 4
		if headerLen > refMaxBlobHeaderSize {
			return out, fmt.Errorf("ref: BlobHeader too large: %d", headerLen)
		}
		if uint64(len(data)-pos) < uint64(headerLen) {
			return out, fmt.Errorf("ref: truncated BlobHeader")
		}
		header := data[pos : pos+int(headerLen)]
		pos += int(headerLen)

		blockType, dataSize, err := refBlobHeader(header)
		if err != nil {
			return out, err
		}
		if len(data)-pos < dataSize {
			return out, fmt.Errorf("ref: truncated Blob")
		}
		out = append(out, refBlock{
			Type:   blockType,
			Offset: offset,
			Blob:   data[pos : pos+dataSize],
		})
		pos += dataSize
	}
}

// refBlobHeader decodes a BlobHeader, returning its type and the Blob's size.
func refBlobHeader(header []byte) (blockType string, dataSize int, err error) {
	var size int64
	s := refScanner{data: header}
	for {
		f, ok, err := s.next()
		if err != nil {
			return "", 0, err
		}
		if !ok {
			break
		}
		switch f.num {
		case 1: // type (string)
			if f.typ != refWireBytes {
				return "", 0, errRefWireType
			}
			blockType = string(f.buf)
		case 3: // datasize (int32)
			if f.typ != refWireVarint {
				return "", 0, errRefWireType
			}
			// The field is an int32, so a value that does not fit one is
			// truncated to 32 bits before the range check below sees it.
			size = int64(refInt32(f.val))
		default:
			// Field 2 is indexdata, which osmbr does not expose.
		}
	}
	// PBF: a Blob is at most 32 MiB, and a zero-length one is meaningless.
	if size <= 0 || size > refMaxBlobSize {
		return "", 0, fmt.Errorf("ref: invalid datasize: %d", size)
	}
	return blockType, int(size), nil
}

// --- Blob decompression ----------------------------------------------------

// refDecompress decodes a Blob and returns its payload.
//
// The zlib stream is inflated by compress/zlib, which independently implements
// the header parse and the Adler-32 check that decompress.go hand-rolls.
func refDecompress(blob []byte) ([]byte, error) {
	var (
		raw      []byte
		zlibData []byte
		rawSize  int
		hasRaw   bool
		hasZlib  bool
	)
	s := refScanner{data: blob}
	for {
		f, ok, err := s.next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		switch f.num {
		case 1: // raw
			if f.typ != refWireBytes {
				return nil, errRefWireType
			}
			raw, hasRaw = f.buf, true
		case 2: // raw_size
			if f.typ != refWireVarint {
				return nil, errRefWireType
			}
			n := refInt32(f.val)
			if n < 0 || n > refMaxBlobSize {
				return nil, fmt.Errorf("ref: invalid raw_size: %d", n)
			}
			rawSize = int(n)
		case 3: // zlib_data
			if f.typ != refWireBytes {
				return nil, errRefWireType
			}
			zlibData, hasZlib = f.buf, true
		case 4, 5, 6, 7: // lzma, bzip2, lz4, zstd
			return nil, fmt.Errorf("ref: unsupported compression in field %d", f.num)
		}
	}

	switch {
	case hasRaw:
		// An uncompressed payload is copied, not aliased: every result of
		// Decompress has the same lifetime, tied to the decompressor rather
		// than to the caller's blob buffer.
		return append([]byte(nil), raw...), nil
	case hasZlib:
		return refInflate(zlibData, rawSize)
	default:
		return nil, errors.New("ref: Blob contains no data")
	}
}

// refInflate inflates a zlib stream and checks it against rawSize.
func refInflate(data []byte, rawSize int) ([]byte, error) {
	// The shortest possible stream: a two-byte header, an empty final DEFLATE
	// block, and the four-byte Adler-32 trailer.
	if len(data) < 8 {
		return nil, fmt.Errorf("ref: zlib stream too short: %d", len(data))
	}
	// RFC 1950 caps CINFO, the window-size exponent, at 7. compress/zlib does
	// not enforce it — it checks only the compression method and the header
	// checksum — so the reference checks it here to stay level with osmbr,
	// which rejects the field outright.
	if cinfo := data[0] >> 4; cinfo > 7 {
		return nil, fmt.Errorf("ref: invalid zlib window size %d", cinfo)
	}

	src := bytes.NewReader(data)
	zr, err := zlib.NewReader(src)
	if err != nil {
		return nil, fmt.Errorf("ref: zlib header: %w", err)
	}
	defer zr.Close()

	// Read one byte past the largest payload PBF allows, so a stream that
	// expands without bound is caught rather than followed.
	out, err := io.ReadAll(io.LimitReader(zr, refMaxBlobSize+1))
	if err != nil {
		return nil, fmt.Errorf("ref: inflate: %w", err)
	}
	if len(out) > refMaxBlobSize {
		return nil, fmt.Errorf("ref: decompressed Blob exceeds %d bytes", refMaxBlobSize)
	}

	// compress/zlib consumes the Adler-32 trailer and stops. Because src is an
	// io.ByteReader, flate never reads past the final DEFLATE block, so
	// anything still unread is trailing garbage: a trailer that is missing,
	// short, or separated from the DEFLATE data.
	//
	// osmbr: a Blob must end exactly at the trailer. protobuf would let the
	// bytes field carry padding, but a Blob whose zlib stream does not fill it
	// has been damaged.
	if src.Len() != 0 {
		return nil, fmt.Errorf("ref: %d bytes after zlib trailer", src.Len())
	}

	// osmbr: raw_size present and positive pins the output length exactly.
	// Zero, whether written explicitly or absent, imposes no length — the two
	// are distinguishable on the wire, but osmbr treats them alike and the
	// reference follows so the oracle tests one behaviour rather than two.
	if rawSize > 0 && len(out) != rawSize {
		return nil, fmt.Errorf("ref: inflated %d bytes, raw_size says %d", len(out), rawSize)
	}
	return out, nil
}

// --- OSMHeader -------------------------------------------------------------

// refHeader mirrors osmbr.Header.
type refHeader struct {
	BBoxLeft, BBoxRight, BBoxTop, BBoxBottom int64
	RequiredFeatures                         []string
	OptionalFeatures                         []string
	WritingProgram                           string
	Source                                   string
	ReplicationTimestamp                     int64
	ReplicationSequenceNumber                int64
	ReplicationBaseURL                       string
}

func refDecodeHeader(data []byte) (refHeader, error) {
	var h refHeader
	s := refScanner{data: data}
	for {
		f, ok, err := s.next()
		if err != nil {
			return h, err
		}
		if !ok {
			break
		}
		switch f.num {
		case 1: // bbox
			if f.typ != refWireBytes {
				return h, errRefWireType
			}
			bs := refScanner{data: f.buf}
			for {
				bf, ok, err := bs.next()
				if err != nil {
					return h, err
				}
				if !ok {
					break
				}
				if bf.num >= 1 && bf.num <= 4 && bf.typ != refWireVarint {
					return h, errRefWireType
				}
				switch bf.num {
				case 1:
					h.BBoxLeft = refSint64(bf.val)
				case 2:
					h.BBoxRight = refSint64(bf.val)
				case 3:
					h.BBoxTop = refSint64(bf.val)
				case 4:
					h.BBoxBottom = refSint64(bf.val)
				}
			}
		case 4, 5, 16, 17, 34: // string fields
			if f.typ != refWireBytes {
				return h, errRefWireType
			}
			switch f.num {
			case 4:
				h.RequiredFeatures = append(h.RequiredFeatures, string(f.buf))
			case 5:
				h.OptionalFeatures = append(h.OptionalFeatures, string(f.buf))
			case 16:
				h.WritingProgram = string(f.buf)
			case 17:
				h.Source = string(f.buf)
			case 34:
				h.ReplicationBaseURL = string(f.buf)
			}
		case 32, 33: // int64 fields
			if f.typ != refWireVarint {
				return h, errRefWireType
			}
			if f.num == 32 {
				h.ReplicationTimestamp = refInt64(f.val)
			} else {
				h.ReplicationSequenceNumber = refInt64(f.val)
			}
		}
	}
	return h, nil
}

// --- PrimitiveBlock --------------------------------------------------------

// refPrimitiveBlock mirrors osmbr.PrimitiveBlock. It has no groups: they are a
// second pass, modelled by refGroups.
type refPrimitiveBlock struct {
	Granularity     int32
	DateGranularity int32
	LatOffset       int64
	LonOffset       int64
	Strings         [][]byte
}

// refDecodePrimitiveBlock mirrors PrimitiveBlock.DecodeFrom, which defers the
// primitivegroup field to PrimitiveBlock.Groups.
//
// Deferring means field 2 is walked past rather than read here, so any wire type
// that can be skipped is acceptable and the group's contents go unexamined. A
// block whose groups are unusable is therefore accepted by this pass and
// rejected by refGroups, which is what a lazy decoder is for.
func refDecodePrimitiveBlock(data []byte) (refPrimitiveBlock, error) {
	// PBF: the granularity fields default to 100 nanodegrees and 1000
	// milliseconds when absent.
	pb := refPrimitiveBlock{Granularity: 100, DateGranularity: 1000}
	s := refScanner{data: data}
	for {
		f, ok, err := s.next()
		if err != nil {
			return pb, err
		}
		if !ok {
			break
		}
		switch f.num {
		case 1: // stringtable
			if f.typ != refWireBytes {
				return pb, errRefWireType
			}
			ss := refScanner{data: f.buf}
			for {
				sf, ok, err := ss.next()
				if err != nil {
					return pb, err
				}
				if !ok {
					break
				}
				if sf.num == 1 {
					if sf.typ != refWireBytes {
						return pb, errRefWireType
					}
					pb.Strings = append(pb.Strings, sf.buf)
				}
			}
		case 2: // primitivegroup — deferred to refGroups
		case 17, 18: // granularity, date_granularity
			if f.typ != refWireVarint {
				return pb, errRefWireType
			}
			if f.num == 17 {
				pb.Granularity = refInt32(f.val)
			} else {
				pb.DateGranularity = refInt32(f.val)
			}
		case 19, 20: // lat_offset, lon_offset
			if f.typ != refWireVarint {
				return pb, errRefWireType
			}
			if f.num == 19 {
				pb.LatOffset = refInt64(f.val)
			} else {
				pb.LonOffset = refInt64(f.val)
			}
		}
	}
	return pb, nil
}

// refGroup is one PrimitiveGroup as GroupScanner yields it.
type refGroup struct {
	Data []byte
	Type int8 // an osmbr.GroupType
}

// refGroups mirrors PrimitiveBlock.Groups, which re-scans the block for
// primitivegroup fields and classifies each by its leading tag.
//
// Unlike the deferring first pass, this one reads the field, so an unusable wire
// type on it is rejected here. It returns the groups yielded before any failure,
// since GroupScanner stops at its first error and reports it separately.
func refGroups(data []byte) ([]refGroup, error) {
	var out []refGroup
	s := refScanner{data: data}
	for {
		f, ok, err := s.next()
		if err != nil {
			return out, err
		}
		if !ok {
			return out, nil
		}
		if f.num != 2 { // primitivegroup
			continue
		}
		if f.typ != refWireBytes {
			return out, errRefWireType
		}
		gt, err := refGroupType(f.buf)
		if err != nil {
			return out, err
		}
		out = append(out, refGroup{Data: f.buf, Type: gt})
	}
}

// refGroupType classifies a PrimitiveGroup by the field number of its first
// field, the way GroupScanner.Type does. The numbers are osmbr.GroupType's.
func refGroupType(groupData []byte) (int8, error) {
	num, ok, err := refTagOnly(groupData)
	if err != nil || !ok {
		return 0, err
	}
	if num >= 1 && num <= 5 {
		return int8(num), nil
	}
	return 0, nil
}

// --- Info ------------------------------------------------------------------

// refInfo mirrors osmbr.InfoBuf.
type refInfo struct {
	Version    int32
	Timestamp  int64
	Changeset  int64
	UID        int32
	UserSID    uint32
	Visible    bool
	HasVisible bool
}

// refDecodeInfoInto decodes an Info message into info without clearing it
// first.
//
// protobuf: info is a singular message field, and a singular message field
// appearing twice merges rather than replaces — a field set by the first
// occurrence survives unless the second sets it too. The caller supplies a
// zeroed refInfo per entity, so a single occurrence behaves as expected.
func refDecodeInfoInto(info *refInfo, data []byte) error {
	s := refScanner{data: data}
	for {
		f, ok, err := s.next()
		if err != nil {
			return err
		}
		if !ok {
			break
		}
		if f.num >= 1 && f.num <= 6 && f.typ != refWireVarint {
			return errRefWireType
		}
		switch f.num {
		case 1:
			info.Version = refInt32(f.val)
		case 2:
			info.Timestamp = refInt64(f.val)
		case 3:
			info.Changeset = refInt64(f.val)
		case 4:
			info.UID = refInt32(f.val)
		case 5:
			// PBF: Info.user_sid is a plain uint32, unlike DenseInfo's
			// delta-coded sint32 of the same name.
			info.UserSID = refUint32(f.val)
		case 6:
			info.Visible = refBool(f.val)
			info.HasVisible = true
		}
	}
	return nil
}

// --- DenseNodes ------------------------------------------------------------

// refDenseInfo mirrors osmbr.DenseInfoBuf.
type refDenseInfo struct {
	Versions   []int32
	Timestamps []int64
	Changesets []int64
	UIDs       []int32
	UserSIDs   []int32
	Visibles   []bool
}

// refDenseNodes mirrors osmbr.DenseNodesBuf plus the DenseInfo beside it.
type refDenseNodes struct {
	IDs      []int64
	Lats     []int64
	Lons     []int64
	KeysVals []int32
	Info     refDenseInfo
}

// refDecodeDenseNodes decodes a DenseNodes PrimitiveGroup. withInfo mirrors
// passing a non-nil *DenseInfoBuf to osmbr.DecodeDenseNodes: with it false the
// denseinfo field is checked for framing but not decoded, and the DenseInfo
// array lengths are not checked against the node count.
//
// protobuf: dense is a singular message field, and a singular message field
// appearing more than once merges. For the delta-coded arrays inside, merging
// means the running totals carry across occurrences, exactly as they do across
// several wire entries of one field.
func refDecodeDenseNodes(groupData []byte, withInfo bool) (refDenseNodes, error) {
	var (
		dn                           refDenseNodes
		prevID, prevLat, prevLon     int64
		prevTimestamp, prevChangeset int64
		prevUID, prevUserSID         int32
	)
	s := refScanner{data: groupData}
	for {
		f, ok, err := s.next()
		if err != nil {
			return dn, err
		}
		if !ok {
			break
		}
		if f.num != 2 { // dense
			continue
		}
		if f.typ != refWireBytes {
			return dn, errRefWireType
		}

		ds := refScanner{data: f.buf}
		for {
			df, ok, err := ds.next()
			if err != nil {
				return dn, err
			}
			if !ok {
				break
			}
			switch df.num {
			case 1: // id (packed sint64, delta)
				vals, err := refVarints(df)
				var decoded []int64
				prevID, decoded = refDeltaSint64(prevID, vals)
				dn.IDs = append(dn.IDs, decoded...)
				if err != nil {
					return dn, err
				}
			case 8: // lat (packed sint64, delta)
				vals, err := refVarints(df)
				var decoded []int64
				prevLat, decoded = refDeltaSint64(prevLat, vals)
				dn.Lats = append(dn.Lats, decoded...)
				if err != nil {
					return dn, err
				}
			case 9: // lon (packed sint64, delta)
				vals, err := refVarints(df)
				var decoded []int64
				prevLon, decoded = refDeltaSint64(prevLon, vals)
				dn.Lons = append(dn.Lons, decoded...)
				if err != nil {
					return dn, err
				}
			case 10: // keys_vals (packed int32, not delta)
				vals, err := refVarints(df)
				for _, v := range vals {
					dn.KeysVals = append(dn.KeysVals, refInt32(v))
				}
				if err != nil {
					return dn, err
				}
			case 5: // denseinfo
				if !withInfo {
					// The caller asked for no metadata, so the field is walked
					// past rather than descended into: any wire type that can
					// be skipped is acceptable, and its contents are not read.
					continue
				}
				if df.typ != refWireBytes {
					return dn, errRefWireType
				}
				is := refScanner{data: df.buf}
				for {
					inf, ok, err := is.next()
					if err != nil {
						return dn, err
					}
					if !ok {
						break
					}
					switch inf.num {
					case 1: // version (packed int32, not delta)
						vals, err := refVarints(inf)
						for _, v := range vals {
							dn.Info.Versions = append(dn.Info.Versions, refInt32(v))
						}
						if err != nil {
							return dn, err
						}
					case 2: // timestamp (packed sint64, delta)
						vals, err := refVarints(inf)
						var decoded []int64
						prevTimestamp, decoded = refDeltaSint64(prevTimestamp, vals)
						dn.Info.Timestamps = append(dn.Info.Timestamps, decoded...)
						if err != nil {
							return dn, err
						}
					case 3: // changeset (packed sint64, delta)
						vals, err := refVarints(inf)
						var decoded []int64
						prevChangeset, decoded = refDeltaSint64(prevChangeset, vals)
						dn.Info.Changesets = append(dn.Info.Changesets, decoded...)
						if err != nil {
							return dn, err
						}
					case 4: // uid (packed sint32, delta)
						vals, err := refVarints(inf)
						var decoded []int32
						prevUID, decoded = refDeltaSint32(prevUID, vals)
						dn.Info.UIDs = append(dn.Info.UIDs, decoded...)
						if err != nil {
							return dn, err
						}
					case 5: // user_sid (packed sint32, delta)
						vals, err := refVarints(inf)
						var decoded []int32
						prevUserSID, decoded = refDeltaSint32(prevUserSID, vals)
						dn.Info.UserSIDs = append(dn.Info.UserSIDs, decoded...)
						if err != nil {
							return dn, err
						}
					case 6: // visible (packed bool)
						vals, err := refVarints(inf)
						for _, v := range vals {
							dn.Info.Visibles = append(dn.Info.Visibles, refBool(v))
						}
						if err != nil {
							return dn, err
						}
					}
				}
			}
		}
	}
	// PBF: id, lat, and lon are parallel arrays, one entry per node. A group
	// with no dense field at all leaves all three empty and passes.
	if len(dn.IDs) != len(dn.Lats) || len(dn.IDs) != len(dn.Lons) {
		return dn, fmt.Errorf("ref: DenseNodes length mismatch: %d/%d/%d",
			len(dn.IDs), len(dn.Lats), len(dn.Lons))
	}
	if withInfo {
		if err := refCheckDenseInfoLen(dn.Info, len(dn.IDs)); err != nil {
			return dn, err
		}
	}
	return dn, nil
}

// refCheckDenseInfoLen reports whether every DenseInfo array is either absent
// or exactly as long as the node arrays it parallels. A file carries metadata
// for every node in a group or for none of them.
func refCheckDenseInfoLen(info refDenseInfo, n int) error {
	for _, a := range []struct {
		name string
		got  int
	}{
		{"version", len(info.Versions)},
		{"timestamp", len(info.Timestamps)},
		{"changeset", len(info.Changesets)},
		{"uid", len(info.UIDs)},
		{"user_sid", len(info.UserSIDs)},
		{"visible", len(info.Visibles)},
	} {
		if a.got != 0 && a.got != n {
			return fmt.Errorf("ref: DenseInfo.%s has %d entries, want %d or 0", a.name, a.got, n)
		}
	}
	return nil
}

// --- Node, Way, Relation ---------------------------------------------------

// refNode mirrors one iteration of osmbr.NodeScanner.Next.
type refNode struct {
	ID   int64
	Lat  int64
	Lon  int64
	Keys []uint32
	Vals []uint32
	Info refInfo
}

// refWay mirrors one iteration of osmbr.WayScanner.Next.
type refWay struct {
	ID   int64
	Keys []uint32
	Vals []uint32
	Refs []int64
	Info refInfo
}

// refRelation mirrors one iteration of osmbr.RelationScanner.Next.
type refRelation struct {
	ID       int64
	Keys     []uint32
	Vals     []uint32
	RolesSID []int32
	MemIDs   []int64
	Types    []int32
	Info     refInfo
}

// refUint32s decodes a repeated uint32 field.
func refUint32s(f refField, dst []uint32) ([]uint32, error) {
	vals, err := refVarints(f)
	for _, v := range vals {
		dst = append(dst, refUint32(v))
	}
	return dst, err
}

// refInt32s decodes a repeated int32 field.
func refInt32s(f refField, dst []int32) ([]int32, error) {
	vals, err := refVarints(f)
	for _, v := range vals {
		dst = append(dst, refInt32(v))
	}
	return dst, err
}

// refDecodeNodes decodes every Node in a PrimitiveGroup, returning those read
// before any failure.
func refDecodeNodes(groupData []byte) ([]refNode, error) {
	var out []refNode
	s := refScanner{data: groupData}
	for {
		f, ok, err := s.next()
		if err != nil {
			return out, err
		}
		if !ok {
			return out, nil
		}
		if f.num != 1 { // nodes
			continue
		}
		if f.typ != refWireBytes {
			return out, errRefWireType
		}
		var n refNode
		ns := refScanner{data: f.buf}
		for {
			nf, ok, err := ns.next()
			if err != nil {
				return out, err
			}
			if !ok {
				break
			}
			switch nf.num {
			case 1: // id (sint64)
				if nf.typ != refWireVarint {
					return out, errRefWireType
				}
				n.ID = refSint64(nf.val)
			case 2: // keys
				if n.Keys, err = refUint32s(nf, n.Keys); err != nil {
					return out, err
				}
			case 3: // vals
				if n.Vals, err = refUint32s(nf, n.Vals); err != nil {
					return out, err
				}
			case 4: // info
				if nf.typ != refWireBytes {
					return out, errRefWireType
				}
				if err = refDecodeInfoInto(&n.Info, nf.buf); err != nil {
					return out, err
				}
			case 8: // lat (sint64)
				if nf.typ != refWireVarint {
					return out, errRefWireType
				}
				n.Lat = refSint64(nf.val)
			case 9: // lon (sint64)
				if nf.typ != refWireVarint {
					return out, errRefWireType
				}
				n.Lon = refSint64(nf.val)
			}
		}
		out = append(out, n)
	}
}

// refDecodeWays decodes every Way in a PrimitiveGroup, returning those read
// before any failure.
func refDecodeWays(groupData []byte) ([]refWay, error) {
	var out []refWay
	s := refScanner{data: groupData}
	for {
		f, ok, err := s.next()
		if err != nil {
			return out, err
		}
		if !ok {
			return out, nil
		}
		if f.num != 3 { // ways
			continue
		}
		if f.typ != refWireBytes {
			return out, errRefWireType
		}
		var w refWay
		var prevRef int64
		ws := refScanner{data: f.buf}
		for {
			wf, ok, err := ws.next()
			if err != nil {
				return out, err
			}
			if !ok {
				break
			}
			switch wf.num {
			case 1: // id (int64)
				if wf.typ != refWireVarint {
					return out, errRefWireType
				}
				w.ID = refInt64(wf.val)
			case 2: // keys
				if w.Keys, err = refUint32s(wf, w.Keys); err != nil {
					return out, err
				}
			case 3: // vals
				if w.Vals, err = refUint32s(wf, w.Vals); err != nil {
					return out, err
				}
			case 4: // info
				if wf.typ != refWireBytes {
					return out, errRefWireType
				}
				if err = refDecodeInfoInto(&w.Info, wf.buf); err != nil {
					return out, err
				}
			case 8: // refs (packed sint64, delta)
				vals, verr := refVarints(wf)
				var decoded []int64
				prevRef, decoded = refDeltaSint64(prevRef, vals)
				w.Refs = append(w.Refs, decoded...)
				if verr != nil {
					return out, verr
				}
			}
		}
		out = append(out, w)
	}
}

// refDecodeRelations decodes every Relation in a PrimitiveGroup, returning
// those read before any failure.
func refDecodeRelations(groupData []byte) ([]refRelation, error) {
	var out []refRelation
	s := refScanner{data: groupData}
	for {
		f, ok, err := s.next()
		if err != nil {
			return out, err
		}
		if !ok {
			return out, nil
		}
		if f.num != 4 { // relations
			continue
		}
		if f.typ != refWireBytes {
			return out, errRefWireType
		}
		var r refRelation
		var prevMemID int64
		rs := refScanner{data: f.buf}
		for {
			rf, ok, err := rs.next()
			if err != nil {
				return out, err
			}
			if !ok {
				break
			}
			switch rf.num {
			case 1: // id (int64)
				if rf.typ != refWireVarint {
					return out, errRefWireType
				}
				r.ID = refInt64(rf.val)
			case 2: // keys
				if r.Keys, err = refUint32s(rf, r.Keys); err != nil {
					return out, err
				}
			case 3: // vals
				if r.Vals, err = refUint32s(rf, r.Vals); err != nil {
					return out, err
				}
			case 4: // info
				if rf.typ != refWireBytes {
					return out, errRefWireType
				}
				if err = refDecodeInfoInto(&r.Info, rf.buf); err != nil {
					return out, err
				}
			case 8: // roles_sid (packed int32, not delta)
				if r.RolesSID, err = refInt32s(rf, r.RolesSID); err != nil {
					return out, err
				}
			case 9: // memids (packed sint64, delta)
				vals, verr := refVarints(rf)
				var decoded []int64
				prevMemID, decoded = refDeltaSint64(prevMemID, vals)
				r.MemIDs = append(r.MemIDs, decoded...)
				if verr != nil {
					return out, verr
				}
			case 10: // types (packed int32, not delta)
				if r.Types, err = refInt32s(rf, r.Types); err != nil {
					return out, err
				}
			}
		}
		out = append(out, r)
	}
}
