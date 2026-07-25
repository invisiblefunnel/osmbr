package osmbr

import (
	"bytes"
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
