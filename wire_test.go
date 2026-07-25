package osmbr

import (
	"bytes"
	"fmt"
	"testing"
)

// varintBytes encodes v as a protobuf varint.
func varintBytes(v uint64) []byte {
	var b []byte
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func tagBytes(field, wire int) []byte { return varintBytes(uint64(field<<3 | wire)) }

func lenDelim(field int, payload []byte) []byte {
	out := tagBytes(field, wireBytes)
	out = append(out, varintBytes(uint64(len(payload)))...)
	return append(out, payload...)
}

func zigzag(v int64) uint64 { return uint64(v<<1) ^ uint64(v>>63) }

func packed(values ...uint64) []byte {
	var out []byte
	for _, v := range values {
		out = append(out, varintBytes(v)...)
	}
	return out
}

func TestMsgScansFieldsAndWireTypes(t *testing.T) {
	var data []byte
	data = append(data, tagBytes(1, wireVarint)...)
	data = append(data, varintBytes(300)...)
	data = append(data, lenDelim(2, []byte("hello"))...)
	data = append(data, tagBytes(3, wireFixed32)...)
	data = append(data, 1, 2, 3, 4)
	data = append(data, tagBytes(4, wireFixed64)...)
	data = append(data, 1, 2, 3, 4, 5, 6, 7, 8)
	// Field 2000 needs a two-byte tag, exercising nextSlow.
	data = append(data, tagBytes(2000, wireVarint)...)
	data = append(data, varintBytes(7)...)

	var (
		m       msg
		gotVar  uint64
		gotStr  []byte
		gotBig  uint64
		fields  []int32
		skipped int
	)
	m.reset(data)
	for m.next() {
		fields = append(fields, m.field)
		switch m.field {
		case 1:
			gotVar = m.varint()
		case 2:
			gotStr = m.bytes()
		case 2000:
			gotBig = m.varint()
		default:
			skipped++
			m.skip()
		}
	}
	if m.err != nil {
		t.Fatalf("err = %v, want nil", m.err)
	}
	if gotVar != 300 {
		t.Errorf("field 1 = %d, want 300", gotVar)
	}
	if string(gotStr) != "hello" {
		t.Errorf("field 2 = %q, want %q", gotStr, "hello")
	}
	if gotBig != 7 {
		t.Errorf("field 2000 = %d, want 7", gotBig)
	}
	if skipped != 2 {
		t.Errorf("skipped %d fields, want 2", skipped)
	}
	want := []int32{1, 2, 3, 4, 2000}
	if len(fields) != len(want) {
		t.Fatalf("fields = %v, want %v", fields, want)
	}
	for i := range want {
		if fields[i] != want[i] {
			t.Fatalf("fields = %v, want %v", fields, want)
		}
	}
}

func TestMsgBytesIsZeroCopy(t *testing.T) {
	data := lenDelim(1, []byte("payload"))
	var m msg
	m.reset(data)
	if !m.next() {
		t.Fatal("next = false")
	}
	got := m.bytes()
	if &got[0] != &data[len(data)-len("payload")] {
		t.Error("bytes copied the payload instead of subslicing it")
	}
}

func TestMsgMalformedInput(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"truncated tag", []byte{0x80}},
		{"truncated varint value", append(tagBytes(1, wireVarint), 0x80)},
		{"length past end", append(tagBytes(1, wireBytes), 0x7f)},
		{"truncated fixed32", append(tagBytes(1, wireFixed32), 1, 2)},
		{"truncated fixed64", append(tagBytes(1, wireFixed64), 1, 2, 3)},
		{"start group wire type", tagBytes(1, 3)},
		{"end group wire type", tagBytes(1, 4)},
		{"varint over 64 bits", append(tagBytes(1, wireVarint),
			0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01)},
		{"overflowing tenth varint byte", append(tagBytes(1, wireVarint),
			0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var m msg
			m.reset(tc.data)
			for i := 0; m.next(); i++ {
				m.skip()
				if i > 64 {
					t.Fatal("scan did not terminate")
				}
			}
			if m.err == nil {
				t.Fatal("err = nil, want an error")
			}
		})
	}
}

func TestMsgAccessorsRejectWrongWireType(t *testing.T) {
	accessors := map[string]struct {
		data   []byte
		decode func(*msg)
	}{
		"bytes":               {taggedVarint(1, 0), func(m *msg) { m.bytes() }},
		"varint":              {lenDelim(1, nil), func(m *msg) { m.varint() }},
		"int64":               {lenDelim(1, nil), func(m *msg) { m.int64() }},
		"int32":               {lenDelim(1, nil), func(m *msg) { m.int32() }},
		"uint32":              {lenDelim(1, nil), func(m *msg) { m.uint32() }},
		"sint64":              {lenDelim(1, nil), func(m *msg) { m.sint64() }},
		"boolean":             {lenDelim(1, nil), func(m *msg) { m.boolean() }},
		"repeatedUint32":      {fixed32Field(1), func(m *msg) { m.repeatedUint32(nil) }},
		"repeatedInt32":       {fixed32Field(1), func(m *msg) { m.repeatedInt32(nil) }},
		"repeatedBool":        {fixed32Field(1), func(m *msg) { m.repeatedBool(nil) }},
		"repeatedDeltaSint64": {fixed32Field(1), func(m *msg) { m.repeatedDeltaSint64(nil) }},
		"repeatedDeltaSint32": {fixed32Field(1), func(m *msg) { m.repeatedDeltaSint32(nil) }},
	}
	for name, tc := range accessors {
		t.Run(name, func(t *testing.T) {
			var m msg
			m.reset(tc.data)
			if !m.next() {
				t.Fatal("next = false")
			}
			tc.decode(&m)
			if m.err != errWireType {
				t.Errorf("err = %v, want %v", m.err, errWireType)
			}
		})
	}
}

func taggedVarint(field int, value uint64) []byte {
	out := tagBytes(field, wireVarint)
	return append(out, varintBytes(value)...)
}

func fixed32Field(field int) []byte {
	out := tagBytes(field, wireFixed32)
	return append(out, 0, 0, 0, 0)
}

func TestMsgRejectsHugeFieldNumber(t *testing.T) {
	// Field number 2^29, one past the protobuf maximum.
	var m msg
	m.reset(varintBytes(uint64(1<<29)<<3 | wireVarint))
	if m.next() {
		t.Fatal("next accepted an out-of-range field number")
	}
	if m.err != errFieldNumber {
		t.Errorf("err = %v, want %v", m.err, errFieldNumber)
	}
}

func TestMsgRejectsFieldNumberZero(t *testing.T) {
	// Field number 0 is not a valid protobuf field. Tag bytes 0x00-0x07 are the
	// single-byte encodings of it, one per wire type.
	for tag := byte(0); tag < 8; tag++ {
		var m msg
		m.reset([]byte{tag, 0x00})
		if m.next() {
			t.Errorf("tag %#02x: next accepted field 0 (field=%d typ=%d)", tag, m.field, m.typ)
		}
		if m.err != errFieldNumber {
			t.Errorf("tag %#02x: err = %v, want %v", tag, m.err, errFieldNumber)
		}
	}

	// The same field number reached through a non-canonical multi-byte tag,
	// which takes the nextSlow path instead.
	var m msg
	m.reset([]byte{0x80, 0x00, 0x00})
	if m.next() {
		t.Errorf("multi-byte tag: next accepted field 0 (field=%d typ=%d)", m.field, m.typ)
	}
	if m.err != errFieldNumber {
		t.Errorf("multi-byte tag: err = %v, want %v", m.err, errFieldNumber)
	}
}

func TestMsgStopsAfterFirstError(t *testing.T) {
	data := append(tagBytes(1, wireBytes), 0x7f) // length runs past the end
	data = append(data, lenDelim(2, []byte("unreachable"))...)
	var m msg
	m.reset(data)
	var seen int
	for m.next() {
		seen++
		m.skip()
	}
	if seen != 1 {
		t.Errorf("scanned %d fields after a failure, want 1", seen)
	}
	if m.err != errTruncated {
		t.Errorf("err = %v, want %v", m.err, errTruncated)
	}
}

func TestRepeatedPackedAndUnpacked(t *testing.T) {
	values := []uint32{0, 1, 127, 128, 300, 1 << 20}

	t.Run("packed", func(t *testing.T) {
		var payload []byte
		for _, v := range values {
			payload = append(payload, varintBytes(uint64(v))...)
		}
		var m msg
		m.reset(lenDelim(1, payload))
		if !m.next() {
			t.Fatal("next = false")
		}
		got := m.repeatedUint32(nil)
		if m.err != nil {
			t.Fatalf("err = %v", m.err)
		}
		assertUint32s(t, got, values)
	})

	t.Run("unpacked", func(t *testing.T) {
		var data []byte
		for _, v := range values {
			data = append(data, tagBytes(1, wireVarint)...)
			data = append(data, varintBytes(uint64(v))...)
		}
		var m msg
		m.reset(data)
		var got []uint32
		for m.next() {
			got = m.repeatedUint32(got)
		}
		if m.err != nil {
			t.Fatalf("err = %v", m.err)
		}
		assertUint32s(t, got, values)
	})
}

func assertUint32s(t *testing.T, got, want []uint32) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestRepeatedInt32Negative(t *testing.T) {
	// Negative int32 values are sign-extended to 10-byte varints on the wire.
	want := []int32{-1, -2147483648, 5}
	var payload []byte
	for _, v := range want {
		payload = append(payload, varintBytes(uint64(int64(v)))...)
	}
	var m msg
	m.reset(lenDelim(1, payload))
	if !m.next() {
		t.Fatal("next = false")
	}
	got := m.repeatedInt32(nil)
	if m.err != nil {
		t.Fatalf("err = %v", m.err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestRepeatedDeltaAccumulatesAcrossEntries(t *testing.T) {
	// A repeated packed field split across two wire entries must continue the
	// delta sum rather than restarting it.
	deltas1 := packed(zigzag(10), zigzag(5))
	deltas2 := packed(zigzag(-3), zigzag(100))
	data := append(lenDelim(1, deltas1), lenDelim(1, deltas2)...)

	var m msg
	m.reset(data)
	var got []int64
	for m.next() {
		got = m.repeatedDeltaSint64(got)
	}
	if m.err != nil {
		t.Fatalf("err = %v", m.err)
	}
	want := []int64{10, 15, 12, 112}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestRepeatedDeltaSint32(t *testing.T) {
	data := lenDelim(1, packed(zigzag(-5), zigzag(3), zigzag(-1)))
	var m msg
	m.reset(data)
	if !m.next() {
		t.Fatal("next = false")
	}
	got := m.repeatedDeltaSint32(nil)
	if m.err != nil {
		t.Fatalf("err = %v", m.err)
	}
	want := []int32{-5, -2, -3}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestRepeatedBool(t *testing.T) {
	data := lenDelim(1, []byte{1, 0, 1, 1})
	var m msg
	m.reset(data)
	if !m.next() {
		t.Fatal("next = false")
	}
	got := m.repeatedBool(nil)
	if m.err != nil {
		t.Fatalf("err = %v", m.err)
	}
	want := []bool{true, false, true, true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// The five repeated* decoders each carry their own copy of the varint loop, for
// reasons the comment above them measures out. That makes divergence between
// copies the failure mode to guard against, so the next three tests run every
// decoder over the same shapes: multi-byte values, the unpacked encoding, and
// an over-long varint.

func TestRepeatedMultiByteValues(t *testing.T) {
	// Values from every varint length, so each decoder's continuation loop runs.
	t.Run("uint32", func(t *testing.T) {
		want := []uint32{0, 127, 128, 300, 1 << 14, 1<<32 - 1}
		var m msg
		m.reset(lenDelim(1, packed(0, 127, 128, 300, 1<<14, 1<<32-1)))
		if !m.next() {
			t.Fatal("next = false")
		}
		got := m.repeatedUint32(nil)
		if m.err != nil {
			t.Fatalf("err = %v", m.err)
		}
		assertUint32s(t, got, want)
	})

	t.Run("int32", func(t *testing.T) {
		want := []int32{0, 127, 128, 300, 1 << 20}
		var m msg
		m.reset(lenDelim(1, packed(0, 127, 128, 300, 1<<20)))
		if !m.next() {
			t.Fatal("next = false")
		}
		got := m.repeatedInt32(nil)
		if m.err != nil {
			t.Fatalf("err = %v", m.err)
		}
		assertInt32s(t, got, want)
	})

	t.Run("bool", func(t *testing.T) {
		// A bool is any varint, including a non-canonical multi-byte one.
		var m msg
		m.reset(lenDelim(1, packed(1, 0, 300, 1<<31, 128)))
		if !m.next() {
			t.Fatal("next = false")
		}
		got := m.repeatedBool(nil)
		if m.err != nil {
			t.Fatalf("err = %v", m.err)
		}
		want := []bool{true, false, true, true, true}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("[%d] got %v, want %v", i, got[i], want[i])
			}
		}
	})

	t.Run("deltaSint64", func(t *testing.T) {
		deltas := []int64{1000, -70000, 64, -64, 1 << 20, 1 << 27, 1 << 40, -1 << 40}
		var vals []uint64
		for _, d := range deltas {
			vals = append(vals, zigzag(d))
		}
		var m msg
		m.reset(lenDelim(1, packed(vals...)))
		if !m.next() {
			t.Fatal("next = false")
		}
		got := m.repeatedDeltaSint64(nil)
		if m.err != nil {
			t.Fatalf("err = %v", m.err)
		}
		var want []int64
		var prev int64
		for _, d := range deltas {
			prev += d
			want = append(want, prev)
		}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("[%d] got %d, want %d", i, got[i], want[i])
			}
		}
	})

	t.Run("deltaSint32", func(t *testing.T) {
		deltas := []int32{1000, -70000, 64, -64, 2147483647, -2147483648, 300}
		var vals []uint64
		for _, d := range deltas {
			vals = append(vals, zigzag(int64(d)))
		}
		var m msg
		m.reset(lenDelim(1, packed(vals...)))
		if !m.next() {
			t.Fatal("next = false")
		}
		got := m.repeatedDeltaSint32(nil)
		if m.err != nil {
			t.Fatalf("err = %v", m.err)
		}
		var want []int32
		var prev int32
		for _, d := range deltas {
			prev += d
			want = append(want, prev)
		}
		assertInt32s(t, got, want)
	})
}

// TestRepeatedUnpackedEveryDecoder covers the wireVarint branch each decoder
// takes when a repeated field arrives one entry per tag.
func TestRepeatedUnpackedEveryDecoder(t *testing.T) {
	// Two entries per field, each a value that needs more than one byte.
	unpacked := func(vals ...uint64) []byte {
		var out []byte
		for _, v := range vals {
			out = append(out, tagBytes(1, wireVarint)...)
			out = append(out, varintBytes(v)...)
		}
		return out
	}

	t.Run("int32", func(t *testing.T) {
		neg := int64(-5) // negative int32s sign-extend to 10-byte varints
		var m msg
		m.reset(unpacked(uint64(neg), 7))
		var got []int32
		for m.next() {
			got = m.repeatedInt32(got)
		}
		if m.err != nil {
			t.Fatalf("err = %v", m.err)
		}
		assertInt32s(t, got, []int32{-5, 7})
	})

	t.Run("bool", func(t *testing.T) {
		var m msg
		m.reset(unpacked(0, 300))
		var got []bool
		for m.next() {
			got = m.repeatedBool(got)
		}
		if m.err != nil {
			t.Fatalf("err = %v", m.err)
		}
		if len(got) != 2 || got[0] || !got[1] {
			t.Errorf("got %v, want [false true]", got)
		}
	})

	t.Run("deltaSint32", func(t *testing.T) {
		var m msg
		m.reset(unpacked(zigzag(-70000), zigzag(5)))
		var got []int32
		for m.next() {
			got = m.repeatedDeltaSint32(got)
		}
		if m.err != nil {
			t.Fatalf("err = %v", m.err)
		}
		assertInt32s(t, got, []int32{-70000, -69995})
	})

	t.Run("deltaSint64", func(t *testing.T) {
		var m msg
		m.reset(unpacked(zigzag(1<<40), zigzag(-5)))
		var got []int64
		for m.next() {
			got = m.repeatedDeltaSint64(got)
		}
		if m.err != nil {
			t.Fatalf("err = %v", m.err)
		}
		if len(got) != 2 || got[0] != 1<<40 || got[1] != 1<<40-5 {
			t.Errorf("got %v, want [%d %d]", got, int64(1)<<40, int64(1)<<40-5)
		}
	})
}

// TestRepeatedOverlongVarint covers the tenth-byte guard in each decoder: a
// varint carrying more than 64 bits of payload is rejected, not truncated.
func TestRepeatedOverlongVarint(t *testing.T) {
	// One valid value, then eleven continuation bytes and a terminator.
	payload := []byte{5, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}
	decoders := map[string]func(*msg){
		"uint32":      func(m *msg) { m.repeatedUint32(nil) },
		"int32":       func(m *msg) { m.repeatedInt32(nil) },
		"bool":        func(m *msg) { m.repeatedBool(nil) },
		"deltaSint64": func(m *msg) { m.repeatedDeltaSint64(nil) },
		"deltaSint32": func(m *msg) { m.repeatedDeltaSint32(nil) },
	}
	for name, decode := range decoders {
		t.Run(name, func(t *testing.T) {
			var m msg
			m.reset(lenDelim(1, payload))
			if !m.next() {
				t.Fatal("next = false")
			}
			decode(&m)
			if m.err != errVarint {
				t.Errorf("err = %v, want %v", m.err, errVarint)
			}
		})
	}
}

func TestRepeatedOverflowingTenthVarintByte(t *testing.T) {
	// The tenth byte of a uint64 varint may carry only bit 63. A terminal byte
	// greater than one has payload bits beyond uint64 and must not be truncated.
	overflow := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02}
	payload := append([]byte{5}, overflow...)
	decoders := map[string]func(*msg){
		"uint32":      func(m *msg) { m.repeatedUint32(nil) },
		"int32":       func(m *msg) { m.repeatedInt32(nil) },
		"bool":        func(m *msg) { m.repeatedBool(nil) },
		"deltaSint64": func(m *msg) { m.repeatedDeltaSint64(nil) },
		"deltaSint32": func(m *msg) { m.repeatedDeltaSint32(nil) },
	}
	for name, decode := range decoders {
		t.Run(name, func(t *testing.T) {
			var m msg
			m.reset(lenDelim(1, payload))
			if !m.next() {
				t.Fatal("next = false")
			}
			decode(&m)
			if m.err != errVarint {
				t.Errorf("err = %v, want %v", m.err, errVarint)
			}
		})
	}
}

func assertInt32s(t *testing.T, got, want []int32) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestRepeatedTruncatedPayload(t *testing.T) {
	// Each packed payload ends mid-varint, so every decoder must record an
	// error rather than run off the end.
	trailing := []byte{0x80}
	decoders := map[string]func(*msg){
		"uint32":      func(m *msg) { m.repeatedUint32(nil) },
		"int32":       func(m *msg) { m.repeatedInt32(nil) },
		"bool":        func(m *msg) { m.repeatedBool(nil) },
		"deltaSint64": func(m *msg) { m.repeatedDeltaSint64(nil) },
		"deltaSint32": func(m *msg) { m.repeatedDeltaSint32(nil) },
	}
	for name, decode := range decoders {
		t.Run(name, func(t *testing.T) {
			var m msg
			m.reset(lenDelim(1, append([]byte{5}, trailing...)))
			if !m.next() {
				t.Fatal("next = false")
			}
			decode(&m)
			if m.err == nil {
				t.Fatal("err = nil, want an error")
			}
		})
	}
}

func TestRepeatedDeltaSint64TruncatedUnrolledVarint(t *testing.T) {
	// Exercise the bounds check before each unrolled byte and the handoff to
	// the checked long-varint loop after byte five.
	for n := 1; n <= 5; n++ {
		t.Run(fmt.Sprintf("after_byte_%d", n), func(t *testing.T) {
			payload := append([]byte{5}, bytes.Repeat([]byte{0x80}, n)...)
			var m msg
			m.reset(lenDelim(1, payload))
			if !m.next() {
				t.Fatal("next = false")
			}
			got := m.repeatedDeltaSint64(nil)
			if m.err != errTruncated {
				t.Errorf("err = %v, want %v; decoded %v", m.err, errTruncated, got)
			}
		})
	}
}

func TestRepeatedReusesCapacity(t *testing.T) {
	data := lenDelim(1, packed(1, 2, 3))
	dst := make([]uint32, 0, 16)
	base := &dst[:1][0]
	var m msg
	m.reset(data)
	if !m.next() {
		t.Fatal("next = false")
	}
	got := m.repeatedUint32(dst)
	if m.err != nil {
		t.Fatalf("err = %v", m.err)
	}
	if &got[0] != base {
		t.Error("repeatedUint32 reallocated a buffer that already had capacity")
	}
}

func TestUnzig64(t *testing.T) {
	cases := []struct {
		in   uint64
		want int64
	}{
		{0, 0}, {1, -1}, {2, 1}, {3, -2}, {4294967294, 2147483647},
		{4294967295, -2147483648},
	}
	for _, tc := range cases {
		if got := unzig64(tc.in); got != tc.want {
			t.Errorf("unzig64(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
	// Round-trip the extremes.
	for _, v := range []int64{-1 << 63, -1, 0, 1, 1<<63 - 1} {
		if got := unzig64(zigzag(v)); got != v {
			t.Errorf("unzig64(zigzag(%d)) = %d", v, got)
		}
	}
}

func TestMsgResetClearsState(t *testing.T) {
	var m msg
	m.reset([]byte{0x80}) // truncated tag
	if m.next() {
		t.Fatal("next = true on truncated tag")
	}
	if m.err == nil {
		t.Fatal("err = nil after truncated tag")
	}
	m.reset(lenDelim(1, []byte("ok")))
	if m.err != nil {
		t.Errorf("err = %v after reset, want nil", m.err)
	}
	if !m.next() {
		t.Fatal("next = false after reset")
	}
	if !bytes.Equal(m.bytes(), []byte("ok")) {
		t.Error("bytes did not return the payload after reset")
	}
}
