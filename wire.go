package osmbr

import "errors"

// Protobuf wire types.
// https://protobuf.dev/programming-guides/encoding/
const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
	wireFixed32 = 5
)

// maxFieldNumber is the largest field number protobuf permits (2^29-1).
const maxFieldNumber = 1<<29 - 1

var (
	errTruncated   = errors.New("truncated protobuf field")
	errVarint      = errors.New("malformed varint")
	errFieldNumber = errors.New("field number out of range")
	errWireType    = errors.New("unsupported wire type")
)

// msg scans a protobuf message body field by field. The zero value is ready
// to use after reset. It keeps no state beyond a cursor into the caller's
// bytes, so every value it yields is a subslice of the original buffer.
//
//	var m msg
//	m.reset(data)
//	for m.next() {
//		switch m.field {
//		case 1:
//			id = m.int64()
//		default:
//			m.skip()
//		}
//	}
//	if m.err != nil { ... }
//
// Errors are sticky: the first failure is recorded in err, the cursor is
// emptied so next reports false, and the accessors return zero values from
// then on. Callers check err once, after the loop. Returning errors from the
// accessors instead pushes them over the inliner's budget, which costs more
// than the scan itself.
type msg struct {
	data  []byte
	i     int // read cursor into data
	field int32
	typ   uint8
	err   error
}

func (m *msg) reset(b []byte) {
	m.data = b
	m.i = 0
	m.field = 0
	m.typ = 0
	m.err = nil
}

// next advances to the next field, reporting whether one was read.
//
// Field numbers 1 through 15 encode as a single tag byte, which covers every
// field osmbr reads in the hot path; everything else falls through to nextSlow.
//
// The fast path's guard is one comparison doing two jobs. Tag bytes 0x00-0x07
// are the single-byte encodings of field number 0, which protobuf forbids;
// subtracting 8 wraps them past the threshold, so they leave the fast path
// alongside multi-byte tags and get rejected in nextSlow. Written as two
// comparisons instead, the extra branch costs ~8% of a scan-heavy decode,
// because next is small enough that one more compare is a real fraction of it.
func (m *msg) next() bool {
	if m.i >= len(m.data) {
		return false
	}
	if c := m.data[m.i]; c-8 < 0x78 {
		m.i++
		m.field = int32(c >> 3)
		m.typ = c & 7
		return true
	}
	return m.nextSlow()
}

func (m *msg) nextSlow() bool {
	tag := m.rawVarint()
	if m.err != nil {
		return false
	}
	// Rejects field number 0 from both the single-byte tags routed here by next
	// and the non-canonical multi-byte forms (0x80 0x00 and friends).
	if num := tag >> 3; num == 0 || num > maxFieldNumber {
		m.fail(errFieldNumber)
		return false
	}
	m.field = int32(tag >> 3)
	m.typ = uint8(tag & 7)
	return true
}

// fail records err and ends the scan. The first error wins.
func (m *msg) fail(err error) {
	if m.err == nil {
		m.err = err
	}
	m.i = len(m.data)
}

// skip advances past the current field's value.
func (m *msg) skip() {
	switch m.typ {
	case wireVarint:
		m.rawVarint()
	case wireBytes:
		m.bytes()
	case wireFixed64:
		if len(m.data)-m.i < 8 {
			m.fail(errTruncated)
			return
		}
		m.i += 8
	case wireFixed32:
		if len(m.data)-m.i < 4 {
			m.fail(errTruncated)
			return
		}
		m.i += 4
	default:
		m.fail(errWireType)
	}
}

// rawVarint reads a varint at the cursor without checking the current wire
// type. Tags and length prefixes use it because they are not field values.
//
// Two things about this loop are load-bearing, both measured on the bundled
// extract. It indexes m.data from m.i rather than ranging over m.data[m.i:],
// because building that subslice on every call cost 35% of the string-table
// scan in PrimitiveBlock.DecodeFrom. And it is kept just inside the inliner's
// budget so it folds into its callers, which is where the rest of the scanning
// cost would otherwise sit — hence also the single error for both truncation
// and overflow, since a second error site pushes it over.
func (m *msg) rawVarint() (v uint64) {
	if m.err != nil {
		return
	}
	var shift uint
	for i := m.i; i < len(m.data); i++ {
		c := uint64(m.data[i])
		// On the tenth byte (shift 63), only 0 and 1 survive this
		// round-trip. Earlier bytes have room for all eight bits.
		if c<<shift>>shift != c {
			break
		}
		v |= (c & 0x7f) << shift
		if c < 0x80 {
			m.i = i + 1
			return
		}
		shift += 7
	}
	m.err = errVarint
	m.i = len(m.data)
	return
}

// varint returns the current varint field's value.
func (m *msg) varint() uint64 {
	if m.typ != wireVarint {
		m.fail(errWireType)
		return 0
	}
	return m.rawVarint()
}

// bytes returns the current length-delimited field's payload as a subslice of
// the scanned buffer. No copy is made.
func (m *msg) bytes() []byte {
	if m.typ != wireBytes {
		m.fail(errWireType)
		return nil
	}
	n := m.rawVarint()
	if n > uint64(len(m.data)-m.i) {
		m.fail(errTruncated)
		return nil
	}
	b := m.data[m.i : m.i+int(n)]
	m.i += int(n)
	return b
}

func (m *msg) int64() int64 { return int64(m.varint()) }

func (m *msg) int32() int32 { return int32(m.varint()) }

func (m *msg) uint32() uint32 { return uint32(m.varint()) }

func (m *msg) sint64() int64 { return unzig64(m.varint()) }

func (m *msg) boolean() bool { return m.varint() != 0 }

// unzig64 reverses protobuf's zigzag encoding.
func unzig64(v uint64) int64 {
	return int64(v>>1) ^ -int64(v&1)
}

// The repeated* decoders below all accept both the packed and the unpacked
// encoding of a repeated scalar field, and all repeat the same varint loop
// instead of sharing a generic one.
//
// That duplication is deliberate. These loops are the innermost code in the
// library, and on real OSM data — benchmarked over every packed field in the
// bundled extract — each abstraction that read better measured slower: making
// the loop generic over the element type cost 13%, moving it behind a shared
// helper call cost 6%, and pre-sizing dst from a varint count instead of
// letting append grow it cost a further 16%. Plain append reaches its
// steady-state capacity within the first few blocks and does not allocate
// after that, which is the property that actually matters here.
//
// Each loop peels off the single-byte case ahead of the continuation loop:
// OSM packs string-table indices and small deltas, so most values are one
// byte and never reach the inner loop.

// repeatedDeltaSint64 appends the field's zigzag values to dst, delta-decoding
// them against a running total. The total starts from the last value already
// in dst, so a repeated field split across several wire entries accumulates
// correctly. Fusing the sum into the decode loop avoids a second pass.
func (m *msg) repeatedDeltaSint64(dst []int64) []int64 {
	var prev int64
	if len(dst) > 0 {
		prev = dst[len(dst)-1]
	}
	if m.typ == wireVarint {
		return append(dst, prev+unzig64(m.rawVarint()))
	}
	data := m.bytes()
	for i := 0; i < len(data); {
		b := uint64(data[i])
		i++
		if b < 0x80 {
			prev += int64(b>>1) ^ -int64(b&1)
			dst = append(dst, prev)
			continue
		}
		v := b & 0x7f
		// Real-planet ID, coordinate, and reference deltas almost always end
		// by byte five. Unroll those bytes so the tenth-byte overflow guard
		// stays on the rare long-varint path without adding a helper call.
		if i >= len(data) {
			m.fail(errTruncated)
			return dst
		}
		b = uint64(data[i])
		i++
		v |= (b & 0x7f) << 7
		if b < 0x80 {
			goto decoded
		}
		if i >= len(data) {
			m.fail(errTruncated)
			return dst
		}
		b = uint64(data[i])
		i++
		v |= (b & 0x7f) << 14
		if b < 0x80 {
			goto decoded
		}
		if i >= len(data) {
			m.fail(errTruncated)
			return dst
		}
		b = uint64(data[i])
		i++
		v |= (b & 0x7f) << 21
		if b < 0x80 {
			goto decoded
		}
		if i >= len(data) {
			m.fail(errTruncated)
			return dst
		}
		b = uint64(data[i])
		i++
		v |= (b & 0x7f) << 28
		if b < 0x80 {
			goto decoded
		}
		for shift := uint(35); ; shift += 7 {
			if i >= len(data) {
				m.fail(errTruncated)
				return dst
			}
			b = uint64(data[i])
			i++
			if shift == 63 && b > 1 {
				m.fail(errVarint)
				return dst
			}
			v |= (b & 0x7f) << shift
			if b < 0x80 {
				break
			}
		}
	decoded:
		prev += int64(v>>1) ^ -int64(v&1)
		dst = append(dst, prev)
	}
	return dst
}

// repeatedDeltaSint32 is repeatedDeltaSint64 for sint32 fields.
func (m *msg) repeatedDeltaSint32(dst []int32) []int32 {
	var prev int32
	if len(dst) > 0 {
		prev = dst[len(dst)-1]
	}
	if m.typ == wireVarint {
		return append(dst, prev+int32(unzig64(m.rawVarint())))
	}
	data := m.bytes()
	for i := 0; i < len(data); {
		b := uint64(data[i])
		i++
		if b < 0x80 {
			prev += int32(b>>1) ^ -int32(b&1)
			dst = append(dst, prev)
			continue
		}
		v := b & 0x7f
		shift := uint(7)
		for {
			if i >= len(data) {
				m.fail(errTruncated)
				return dst
			}
			b = uint64(data[i])
			i++
			if shift == 63 && b > 1 {
				m.fail(errVarint)
				return dst
			}
			v |= (b & 0x7f) << shift
			if b < 0x80 {
				break
			}
			shift += 7
		}
		prev += int32(unzig64(v))
		dst = append(dst, prev)
	}
	return dst
}

// repeatedUint32 appends the field's plain varint values to dst.
func (m *msg) repeatedUint32(dst []uint32) []uint32 {
	if m.typ == wireVarint {
		return append(dst, uint32(m.rawVarint()))
	}
	data := m.bytes()
	for i := 0; i < len(data); {
		b := uint64(data[i])
		i++
		if b < 0x80 {
			dst = append(dst, uint32(b))
			continue
		}
		v := b & 0x7f
		shift := uint(7)
		for {
			if i >= len(data) {
				m.fail(errTruncated)
				return dst
			}
			b = uint64(data[i])
			i++
			if shift == 63 && b > 1 {
				m.fail(errVarint)
				return dst
			}
			v |= (b & 0x7f) << shift
			if b < 0x80 {
				break
			}
			shift += 7
		}
		dst = append(dst, uint32(v))
	}
	return dst
}

// repeatedInt32 is repeatedUint32 for int32 fields. Negative values are
// encoded as 10-byte varints, so the value is truncated rather than ranged.
func (m *msg) repeatedInt32(dst []int32) []int32 {
	if m.typ == wireVarint {
		return append(dst, int32(m.rawVarint()))
	}
	data := m.bytes()
	for i := 0; i < len(data); {
		b := uint64(data[i])
		i++
		if b < 0x80 {
			dst = append(dst, int32(b))
			continue
		}
		v := b & 0x7f
		shift := uint(7)
		for {
			if i >= len(data) {
				m.fail(errTruncated)
				return dst
			}
			b = uint64(data[i])
			i++
			if shift == 63 && b > 1 {
				m.fail(errVarint)
				return dst
			}
			v |= (b & 0x7f) << shift
			if b < 0x80 {
				break
			}
			shift += 7
		}
		dst = append(dst, int32(v))
	}
	return dst
}

// repeatedBool appends the field's varint values to dst as booleans.
func (m *msg) repeatedBool(dst []bool) []bool {
	if m.typ == wireVarint {
		return append(dst, m.rawVarint() != 0)
	}
	data := m.bytes()
	for i := 0; i < len(data); {
		b := uint64(data[i])
		i++
		if b < 0x80 {
			dst = append(dst, b != 0)
			continue
		}
		v := b & 0x7f
		shift := uint(7)
		for {
			if i >= len(data) {
				m.fail(errTruncated)
				return dst
			}
			b = uint64(data[i])
			i++
			if shift == 63 && b > 1 {
				m.fail(errVarint)
				return dst
			}
			v |= (b & 0x7f) << shift
			if b < 0x80 {
				break
			}
			shift += 7
		}
		dst = append(dst, v != 0)
	}
	return dst
}
