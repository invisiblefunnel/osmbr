package osmbr_test

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/invisiblefunnel/osmbr"
)

// pbfFrame builds a BlockReader frame: 4-byte big-endian header length,
// then BlobHeader bytes, then dataSize Blob bytes.
func pbfFrame(blockType string, blob []byte) []byte {
	header := append(pbLenDelim(1, []byte(blockType)), pbVarintField(3, uint64(len(blob)))...)
	out := make([]byte, 4, 4+len(header)+len(blob))
	binary.BigEndian.PutUint32(out, uint32(len(header)))
	out = append(out, header...)
	out = append(out, blob...)
	return out
}

func TestBlockReaderEmptyInput(t *testing.T) {
	br := osmbr.NewBlockReader(bytes.NewReader(nil))
	if _, ok := br.NextInto(nil); ok {
		t.Fatal("NextInto on empty input should return false")
	}
	if err := br.Err(); err != nil {
		t.Errorf("Err on empty input = %v, want nil", err)
	}
}

func TestBlockReaderTruncatedHeaderLength(t *testing.T) {
	// Only 2 bytes — not enough for the 4-byte length prefix.
	br := osmbr.NewBlockReader(bytes.NewReader([]byte{0, 0}))
	if _, ok := br.NextInto(nil); ok {
		t.Fatal("NextInto on partial length prefix should return false")
	}
	if err := br.Err(); err != nil {
		t.Errorf("Err on partial length prefix = %v, want nil (clean EOF)", err)
	}
}

func TestBlockReaderTruncatedHeader(t *testing.T) {
	// Length prefix says 100 bytes of header but only 5 bytes follow.
	data := []byte{0, 0, 0, 100, 1, 2, 3, 4, 5}
	br := osmbr.NewBlockReader(bytes.NewReader(data))
	if _, ok := br.NextInto(nil); ok {
		t.Fatal("NextInto on truncated header should return false")
	}
	if err := br.Err(); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestBlockReaderTruncatedBlob(t *testing.T) {
	// Valid header announcing 200 bytes of blob, but only 10 bytes follow.
	frame := pbfFrame("OSMData", make([]byte, 200))
	br := osmbr.NewBlockReader(bytes.NewReader(frame[:len(frame)-190]))
	if _, ok := br.NextInto(nil); ok {
		t.Fatal("NextInto on truncated blob should return false")
	}
	if err := br.Err(); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestBlockReaderOversizedHeader(t *testing.T) {
	// Length prefix exceeds the spec maximum (64 KiB).
	data := []byte{0x00, 0x01, 0x00, 0x01} // 65537
	br := osmbr.NewBlockReader(bytes.NewReader(data))
	if _, ok := br.NextInto(nil); ok {
		t.Fatal("NextInto on oversized header should return false")
	}
	err := br.Err()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "BlobHeader too large") {
		t.Errorf("error %q does not mention BlobHeader too large", err)
	}
}

func TestBlockReaderInvalidDataSize(t *testing.T) {
	cases := []struct {
		name string
		size uint64
	}{
		{"zero", 0},
		{"too large", 32*1024*1024 + 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := append(pbLenDelim(1, []byte("OSMData")), pbVarintField(3, tc.size)...)
			out := make([]byte, 4, 4+len(header))
			binary.BigEndian.PutUint32(out, uint32(len(header)))
			out = append(out, header...)
			br := osmbr.NewBlockReader(bytes.NewReader(out))
			if _, ok := br.NextInto(nil); ok {
				t.Fatal("NextInto with invalid datasize should return false")
			}
			err := br.Err()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), "datasize") {
				t.Errorf("error %q does not mention datasize", err)
			}
		})
	}
}

func TestBlockReaderUnknownBlockType(t *testing.T) {
	// Unknown block types should round-trip the raw string via Type().
	frame := pbfFrame("CustomType", []byte{0x0a, 0x00}) // any non-empty blob
	br := osmbr.NewBlockReader(bytes.NewReader(frame))
	if _, ok := br.NextInto(nil); !ok {
		t.Fatalf("NextInto returned false: %v", br.Err())
	}
	if got := br.Type(); got != "CustomType" {
		t.Errorf("Type = %q, want %q", got, "CustomType")
	}
}

func TestBlockReaderReset(t *testing.T) {
	blob := pbLenDelim(1, []byte("first"))
	frame := pbfFrame("OSMData", blob)

	br := osmbr.NewBlockReader(bytes.NewReader(frame))
	got, ok := br.NextInto(nil)
	if !ok {
		t.Fatalf("NextInto returned false: %v", br.Err())
	}
	if string(got) != string(blob) {
		t.Errorf("first walk blob = %x, want %x", got, blob)
	}
	firstOffset := br.Offset()
	if _, ok := br.NextInto(nil); ok {
		t.Fatal("NextInto should return false after the only block")
	}

	// After Reset, a second walk over the same input must look identical
	// to a freshly-constructed reader's.
	blob2 := pbLenDelim(1, []byte("second"))
	frame2 := pbfFrame("OSMData", blob2)
	br.Reset(bytes.NewReader(frame2))

	if br.Err() != nil {
		t.Errorf("Err after Reset = %v, want nil", br.Err())
	}
	if br.Type() != "" {
		t.Errorf("Type after Reset = %q, want empty", br.Type())
	}
	if br.Offset() != 0 {
		t.Errorf("Offset after Reset = %d, want 0", br.Offset())
	}
	got, ok = br.NextInto(got[:0])
	if !ok {
		t.Fatalf("NextInto after Reset returned false: %v", br.Err())
	}
	if br.Offset() != 0 {
		t.Errorf("Offset after Reset + NextInto = %d, want 0", br.Offset())
	}
	if !bytes.Equal(got, blob2) {
		t.Errorf("blob after Reset = %x, want %x", got, blob2)
	}
	_ = firstOffset // keep the first-walk check explicit
}

// TestBlockReaderResetAfterError confirms Reset clears a prior error so
// the reader can be reused on fresh input.
func TestBlockReaderResetAfterError(t *testing.T) {
	// Truncated input -> Err != nil after NextInto.
	br := osmbr.NewBlockReader(bytes.NewReader([]byte{0, 0, 0, 100, 1, 2, 3}))
	if _, ok := br.NextInto(nil); ok {
		t.Fatal("NextInto on truncated input should return false")
	}
	if br.Err() == nil {
		t.Fatal("expected error before Reset")
	}

	// Reset onto a valid frame — should walk cleanly.
	frame := pbfFrame("OSMData", pbLenDelim(1, []byte("ok")))
	br.Reset(bytes.NewReader(frame))
	if err := br.Err(); err != nil {
		t.Errorf("Err after Reset = %v, want nil", err)
	}
	if _, ok := br.NextInto(nil); !ok {
		t.Fatalf("NextInto after Reset returned false: %v", br.Err())
	}
}

func TestBlockReaderRoundTripSyntheticFrame(t *testing.T) {
	blob := pbLenDelim(1, []byte("payload")) // raw blob
	frame := pbfFrame("OSMData", blob)
	br := osmbr.NewBlockReader(bytes.NewReader(frame))
	got, ok := br.NextInto(nil)
	if !ok {
		t.Fatalf("NextInto returned false: %v", br.Err())
	}
	if br.Type() != "OSMData" {
		t.Errorf("Type = %q, want %q", br.Type(), "OSMData")
	}
	if !bytes.Equal(got, blob) {
		t.Errorf("blob = %x, want %x", got, blob)
	}
	if _, ok := br.NextInto(nil); ok {
		t.Fatal("NextInto should return false after the only block")
	}
	if err := br.Err(); err != nil {
		t.Errorf("Err = %v, want nil", err)
	}
}

func TestBlockReaderNextInto(t *testing.T) {
	blob1 := []byte{0x01, 0x02, 0x03}
	blob2 := []byte{0x04, 0x05}
	frame1 := pbfFrame("OSMHeader", blob1)
	frame2 := pbfFrame("OSMData", blob2)
	input := append(append([]byte(nil), frame1...), frame2...)

	br := osmbr.NewBlockReader(bytes.NewReader(input))
	got, ok := br.NextInto(make([]byte, 0, 16))
	if !ok {
		t.Fatalf("NextInto first block returned false: %v", br.Err())
	}
	if br.Type() != "OSMHeader" {
		t.Errorf("first Type = %q, want OSMHeader", br.Type())
	}
	if br.Offset() != 0 {
		t.Errorf("first Offset = %d, want 0", br.Offset())
	}
	if !bytes.Equal(got, blob1) {
		t.Errorf("first blob = %x, want %x", got, blob1)
	}

	got, ok = br.NextInto(make([]byte, 0, 16))
	if !ok {
		t.Fatalf("NextInto second block returned false: %v", br.Err())
	}
	if br.Type() != "OSMData" {
		t.Errorf("second Type = %q, want OSMData", br.Type())
	}
	if br.Offset() != int64(len(frame1)) {
		t.Errorf("second Offset = %d, want %d", br.Offset(), len(frame1))
	}
	if !bytes.Equal(got, blob2) {
		t.Errorf("second blob = %x, want %x", got, blob2)
	}
	if _, ok := br.NextInto(nil); ok {
		t.Fatal("NextInto should return false after two blocks")
	}
	if err := br.Err(); err != nil {
		t.Errorf("Err = %v, want nil", err)
	}
}

func TestBlockReaderNextIntoReusesCallerBuffer(t *testing.T) {
	blob := []byte{0x0a, 0x0b, 0x0c}
	frame := pbfFrame("OSMData", blob)
	dst := make([]byte, 0, 16)
	base := dst[:1]

	br := osmbr.NewBlockReader(bytes.NewReader(frame))
	got, ok := br.NextInto(dst)
	if !ok {
		t.Fatalf("NextInto returned false: %v", br.Err())
	}
	if !bytes.Equal(got, blob) {
		t.Errorf("blob = %x, want %x", got, blob)
	}
	if &got[0] != &base[0] {
		t.Error("NextInto did not reuse caller buffer with sufficient capacity")
	}
	if cap(got) != cap(dst) {
		t.Errorf("cap(blob) = %d, want %d", cap(got), cap(dst))
	}
}

func TestBlockReaderNextIntoGrowsCallerBuffer(t *testing.T) {
	blob := []byte{0x0a, 0x0b, 0x0c}
	frame := pbfFrame("OSMData", blob)
	dst := make([]byte, 0, 1)
	base := dst[:1]

	br := osmbr.NewBlockReader(bytes.NewReader(frame))
	got, ok := br.NextInto(dst)
	if !ok {
		t.Fatalf("NextInto returned false: %v", br.Err())
	}
	if !bytes.Equal(got, blob) {
		t.Errorf("blob = %x, want %x", got, blob)
	}
	if &got[0] == &base[0] {
		t.Error("NextInto reused caller buffer with insufficient capacity")
	}
	if len(got) != len(blob) {
		t.Errorf("len(blob) = %d, want %d", len(got), len(blob))
	}
}

func TestBlockReaderNextIntoRetainedBlobSurvivesAdvance(t *testing.T) {
	blob1 := []byte("first")
	blob2 := []byte("second")
	input := append(pbfFrame("OSMData", blob1), pbfFrame("OSMData", blob2)...)

	br := osmbr.NewBlockReader(bytes.NewReader(input))
	retained, ok := br.NextInto(make([]byte, 0, len(blob1)))
	if !ok {
		t.Fatalf("NextInto first block returned false: %v", br.Err())
	}
	got, ok := br.NextInto(make([]byte, 0, len(blob2)))
	if !ok {
		t.Fatalf("NextInto second block returned false: %v", br.Err())
	}
	if !bytes.Equal(got, blob2) {
		t.Errorf("second blob = %x, want %x", got, blob2)
	}
	if !bytes.Equal(retained, blob1) {
		t.Errorf("retained first blob after NextInto = %x, want %x", retained, blob1)
	}
}

func TestBlockReaderNextIntoEOFAndError(t *testing.T) {
	br := osmbr.NewBlockReader(bytes.NewReader(nil))
	if blob, ok := br.NextInto(make([]byte, 0, 8)); ok {
		t.Fatalf("NextInto on empty input returned (%x, true), want false", blob)
	}
	if err := br.Err(); err != nil {
		t.Errorf("Err on empty input = %v, want nil", err)
	}

	frame := pbfFrame("OSMData", make([]byte, 16))
	br = osmbr.NewBlockReader(bytes.NewReader(frame[:len(frame)-4]))
	if blob, ok := br.NextInto(make([]byte, 0, 8)); ok {
		t.Fatalf("NextInto on truncated blob returned (%x, true), want false", blob)
	}
	if err := br.Err(); err == nil {
		t.Fatal("expected error on truncated blob, got nil")
	}
}

func TestBlockReaderZeroValue(t *testing.T) {
	// The zero value must be usable after Reset, so callers can embed a
	// BlockReader in a struct they already own.
	blob := pbLenDelim(1, []byte("payload"))
	frame := pbfFrame("OSMData", blob)

	var br osmbr.BlockReader
	br.Reset(bytes.NewReader(frame))
	if !br.Next() {
		t.Fatalf("Next returned false: %v", br.Err())
	}
	if br.Type() != "OSMData" {
		t.Errorf("Type = %q, want OSMData", br.Type())
	}
	if !bytes.Equal(br.Blob(), blob) {
		t.Errorf("Blob = %x, want %x", br.Blob(), blob)
	}
	if br.Next() {
		t.Fatal("Next should return false after the only block")
	}
	if err := br.Err(); err != nil {
		t.Errorf("Err = %v, want nil", err)
	}
}

func TestBlockReaderNextAndBlob(t *testing.T) {
	blob1 := []byte("first")
	blob2 := []byte("second-and-longer")
	input := append(pbfFrame("OSMHeader", blob1), pbfFrame("OSMData", blob2)...)

	br := osmbr.NewBlockReader(bytes.NewReader(input))
	if !br.Next() {
		t.Fatalf("Next returned false: %v", br.Err())
	}
	if br.Type() != "OSMHeader" || !bytes.Equal(br.Blob(), blob1) {
		t.Errorf("first block = (%q, %x), want (OSMHeader, %x)", br.Type(), br.Blob(), blob1)
	}
	if !br.Next() {
		t.Fatalf("Next returned false: %v", br.Err())
	}
	if br.Type() != "OSMData" || !bytes.Equal(br.Blob(), blob2) {
		t.Errorf("second block = (%q, %x), want (OSMData, %x)", br.Type(), br.Blob(), blob2)
	}
	if br.Offset() != int64(len(pbfFrame("OSMHeader", blob1))) {
		t.Errorf("second Offset = %d", br.Offset())
	}
	if br.Next() {
		t.Fatal("Next should return false after two blocks")
	}
	if err := br.Err(); err != nil {
		t.Errorf("Err = %v, want nil", err)
	}
}

// TestBlockReaderNextReusesInternalBuffer checks that a Next walk settles into
// a single backing array rather than reallocating per block.
func TestBlockReaderNextReusesInternalBuffer(t *testing.T) {
	var input []byte
	for i := 0; i < 4; i++ {
		input = append(input, pbfFrame("OSMData", bytes.Repeat([]byte{byte(i)}, 64))...)
	}
	br := osmbr.NewBlockReader(bytes.NewReader(input))
	if !br.Next() {
		t.Fatalf("Next returned false: %v", br.Err())
	}
	first := &br.Blob()[0]
	for br.Next() {
		if &br.Blob()[0] != first {
			t.Fatal("Next reallocated its buffer for a same-sized block")
		}
	}
	if err := br.Err(); err != nil {
		t.Fatal(err)
	}
}

// TestBlockReaderNextIntoPreservesBufferOnEOF pins the contract that a pooled
// caller never loses its buffer when the walk ends.
func TestBlockReaderNextIntoPreservesBufferOnEOF(t *testing.T) {
	dst := make([]byte, 0, 32)
	base := &dst[:1][0]

	t.Run("eof", func(t *testing.T) {
		br := osmbr.NewBlockReader(bytes.NewReader(nil))
		got, ok := br.NextInto(dst)
		if ok {
			t.Fatal("NextInto on empty input returned true")
		}
		if cap(got) != cap(dst) || &got[:1][0] != base {
			t.Errorf("NextInto returned cap %d, want the caller's buffer (cap %d)", cap(got), cap(dst))
		}
	})

	t.Run("error", func(t *testing.T) {
		br := osmbr.NewBlockReader(bytes.NewReader([]byte{0, 0, 0, 100, 1, 2, 3}))
		got, ok := br.NextInto(dst)
		if ok {
			t.Fatal("NextInto on truncated input returned true")
		}
		if br.Err() == nil {
			t.Fatal("expected an error")
		}
		if cap(got) != cap(dst) || &got[:1][0] != base {
			t.Errorf("NextInto returned cap %d, want the caller's buffer (cap %d)", cap(got), cap(dst))
		}
	})
}

// TestBlockReaderLargeBlobHeader exercises the heap fallback for BlobHeaders
// too large for the inline scratch array.
func TestBlockReaderLargeBlobHeader(t *testing.T) {
	blob := []byte("payload")
	// Field 2 (indexdata) is skipped by the decoder; pad it out so the header
	// comfortably exceeds the inline buffer.
	header := pbLenDelim(1, []byte("OSMData"))
	header = append(header, pbLenDelim(2, bytes.Repeat([]byte{0xAB}, 4096))...)
	header = append(header, pbVarintField(3, uint64(len(blob)))...)

	frame := make([]byte, 4, 4+len(header)+len(blob))
	binary.BigEndian.PutUint32(frame, uint32(len(header)))
	frame = append(frame, header...)
	frame = append(frame, blob...)

	br := osmbr.NewBlockReader(bytes.NewReader(frame))
	if !br.Next() {
		t.Fatalf("Next returned false: %v", br.Err())
	}
	if br.Type() != "OSMData" {
		t.Errorf("Type = %q, want OSMData", br.Type())
	}
	if !bytes.Equal(br.Blob(), blob) {
		t.Errorf("Blob = %x, want %x", br.Blob(), blob)
	}
}

func TestBlockReaderNoAllocAfterWarmup(t *testing.T) {
	var input []byte
	for i := 0; i < 8; i++ {
		input = append(input, pbfFrame("OSMData", bytes.Repeat([]byte{byte(i)}, 512))...)
	}
	var (
		br  osmbr.BlockReader
		rdr bytes.Reader
	)
	walk := func() {
		rdr.Reset(input)
		br.Reset(&rdr)
		for br.Next() {
			_ = br.Blob()
		}
		if err := br.Err(); err != nil {
			t.Fatal(err)
		}
	}
	walk() // warm up
	if got := testing.AllocsPerRun(20, walk); got != 0 {
		t.Errorf("allocs per walk = %v, want 0", got)
	}
}
