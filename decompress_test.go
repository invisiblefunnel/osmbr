package osmbr_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/invisiblefunnel/osmbr"
	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/zlib"
)

// pbVarint encodes v as a protobuf varint.
func pbVarint(v uint64) []byte {
	var b []byte
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

// pbTag returns the protobuf tag byte(s) for fieldNumber and wireType.
func pbTag(fieldNumber, wireType int) []byte {
	return pbVarint(uint64(fieldNumber<<3 | wireType))
}

// pbLenDelim returns a length-delimited field encoding for fieldNumber + data.
func pbLenDelim(fieldNumber int, data []byte) []byte {
	out := pbTag(fieldNumber, 2) // wire type 2 = length-delimited
	out = append(out, pbVarint(uint64(len(data)))...)
	return append(out, data...)
}

// pbVarintField returns a varint field encoding for fieldNumber + value.
func pbVarintField(fieldNumber int, value uint64) []byte {
	out := pbTag(fieldNumber, 0) // wire type 0 = varint
	return append(out, pbVarint(value)...)
}

func TestDecompressorRejectsUnsupportedCompression(t *testing.T) {
	cases := []struct {
		name    string
		field   int
		wantSub string
	}{
		{"lzma", 4, "lzma"},
		{"bzip2", 5, "bzip2"},
		{"lz4", 6, "lz4"},
		{"zstd", 7, "zstd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var dec osmbr.Decompressor
			_, err := dec.Decompress(pbLenDelim(tc.field, nil))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not mention %q", err, tc.wantSub)
			}
		})
	}
}

func TestDecompressorRejectsEmptyBlob(t *testing.T) {
	var dec osmbr.Decompressor
	_, err := dec.Decompress(nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no data") {
		t.Errorf("error %q does not mention no data", err)
	}
}

func TestDecompressorRejectsRawSizeTooLarge(t *testing.T) {
	const tooBig = 32*1024*1024 + 1 // one byte past the spec maximum
	blob := append(pbVarintField(2, tooBig), pbLenDelim(3, []byte{0x78, 0x9c})...)
	var dec osmbr.Decompressor
	_, err := dec.Decompress(blob)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "raw_size") {
		t.Errorf("error %q does not mention raw_size", err)
	}
}

func TestDecompressorAcceptsRawBlob(t *testing.T) {
	payload := []byte("hello world")
	blob := pbLenDelim(1, payload) // field 1 = raw
	var dec osmbr.Decompressor
	got, err := dec.Decompress(blob)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Errorf("got %q, want %q", got, payload)
	}
}

// TestDecompressorRawBlobOutlivesInput pins the lifetime contract: every
// Decompress result lives in the Decompressor's own storage, so a caller
// reusing its blob buffer — exactly what BlockReader.Next does — cannot
// rewrite a result the caller still holds.
func TestDecompressorRawBlobOutlivesInput(t *testing.T) {
	const payload = "AAAAAAAAAAAAAAAA"
	blob := pbLenDelim(1, []byte(payload)) // field 1 = raw

	var dec osmbr.Decompressor
	got, err := dec.Decompress(blob)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("got %q, want %q", got, payload)
	}

	// Overwrite the input in place the way a reused read buffer would.
	for i := range blob {
		blob[i] = 'B'
	}
	if string(got) != payload {
		t.Errorf("result followed the input buffer: got %q, want %q", got, payload)
	}
}

// TestDecompressorRawNoAllocAfterWarmup keeps the copy added for the lifetime
// guarantee from costing an allocation per block.
func TestDecompressorRawNoAllocAfterWarmup(t *testing.T) {
	blob := pbLenDelim(1, bytes.Repeat([]byte("raw-payload-"), 500))

	var dec osmbr.Decompressor
	if _, err := dec.Decompress(blob); err != nil { // warm up
		t.Fatal(err)
	}
	got := testing.AllocsPerRun(20, func() {
		if _, err := dec.Decompress(blob); err != nil {
			t.Fatal(err)
		}
	})
	if got != 0 {
		t.Errorf("allocs per raw Decompress = %v, want 0", got)
	}
}

// zlibCompress returns zlib-encoded bytes of src.
func zlibCompress(tb testing.TB, src []byte) []byte {
	tb.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(src); err != nil {
		tb.Fatalf("zlib.Write: %v", err)
	}
	if err := zw.Close(); err != nil {
		tb.Fatalf("zlib.Close: %v", err)
	}
	return buf.Bytes()
}

// zlibBlob returns a Blob protobuf with raw_size (field 2) and zlib_data
// (field 3). If rawSize < 0, the raw_size field is omitted, which sends
// Decompressor.decompress down its read-until-EOF branch.
func zlibBlob(rawSize int, compressed []byte) []byte {
	var out []byte
	if rawSize >= 0 {
		out = pbVarintField(2, uint64(rawSize))
	}
	return append(out, pbLenDelim(3, compressed)...)
}

func TestDecompressorZlibRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte("osmbr-roundtrip-"), 200) // ~3.2 KiB, compresses well
	compressed := zlibCompress(t, payload)
	blob := zlibBlob(len(payload), compressed)

	var dec osmbr.Decompressor
	got, err := dec.Decompress(blob)
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("round-trip mismatch: got %d bytes, want %d", len(got), len(payload))
	}

	// Second call reuses the internal zlib reader — must also succeed.
	got2, err := dec.Decompress(blob)
	if err != nil {
		t.Fatalf("Decompress (reuse): %v", err)
	}
	if !bytes.Equal(got2, payload) {
		t.Errorf("reuse mismatch: got %d bytes, want %d", len(got2), len(payload))
	}
}

func TestDecompressorZlibWithoutRawSize(t *testing.T) {
	// Exercise the read-until-EOF branch (raw_size absent → field 2 not set).
	payload := []byte("no raw_size here")
	compressed := zlibCompress(t, payload)
	blob := zlibBlob(-1, compressed)

	var dec osmbr.Decompressor
	got, err := dec.Decompress(blob)
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("got %q, want %q", got, payload)
	}
}

func TestDecompressorZlibCorrupted(t *testing.T) {
	// Valid zlib header bytes but immediately followed by junk.
	blob := zlibBlob(100, []byte{0x78, 0x9c, 0xff, 0xff, 0xff, 0xff})

	var dec osmbr.Decompressor
	_, err := dec.Decompress(blob)
	if err == nil {
		t.Fatal("expected error on corrupted zlib data")
	}
	if !strings.Contains(err.Error(), "decompress") &&
		!strings.Contains(err.Error(), "zlib") {
		t.Errorf("error %q lacks decompress/zlib context", err)
	}

	// Decompressor must recover for a subsequent valid call.
	payload := []byte("recovered")
	good := zlibBlob(len(payload), zlibCompress(t, payload))
	got, err := dec.Decompress(good)
	if err != nil {
		t.Fatalf("Decompress after error: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("got %q, want %q", got, payload)
	}
}

func TestDecompressorZlibShortPayload(t *testing.T) {
	// raw_size promises 1024 bytes but the actual payload only yields a few.
	payload := []byte("short")
	compressed := zlibCompress(t, payload)
	blob := zlibBlob(1024, compressed) // overclaim rawSize → io.ReadFull error

	var dec osmbr.Decompressor
	_, err := dec.Decompress(blob)
	if err == nil {
		t.Fatal("expected error when rawSize exceeds actual payload")
	}
}

func TestDecompressorChecksum(t *testing.T) {
	payload := bytes.Repeat([]byte("checksum-me-"), 100)
	compressed := zlibCompress(t, payload)

	t.Run("valid", func(t *testing.T) {
		var dec osmbr.Decompressor // zero value verifies
		got, err := dec.Decompress(zlibBlob(len(payload), compressed))
		if err != nil {
			t.Fatalf("Decompress: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Error("round-trip mismatch")
		}
	})

	t.Run("valid without raw_size", func(t *testing.T) {
		var dec osmbr.Decompressor
		got, err := dec.Decompress(zlibBlob(-1, compressed))
		if err != nil {
			t.Fatalf("Decompress: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Error("round-trip mismatch")
		}
	})

	t.Run("corrupt trailer", func(t *testing.T) {
		bad := append([]byte(nil), compressed...)
		bad[len(bad)-1] ^= 0xff // flip bits in the Adler-32 trailer
		blob := zlibBlob(len(payload), bad)

		// Verification is the default, so the corrupt trailer is caught even
		// though the DEFLATE stream itself is intact.
		var on osmbr.Decompressor
		_, err := on.Decompress(blob)
		if err == nil {
			t.Fatal("expected a checksum error")
		}
		if !strings.Contains(err.Error(), "Adler-32") {
			t.Errorf("error %q does not mention Adler-32", err)
		}

		// Opting out lets it through.
		off := osmbr.Decompressor{SkipChecksum: true}
		if _, err := off.Decompress(blob); err != nil {
			t.Fatalf("Decompress with SkipChecksum: %v", err)
		}
	})
}

func TestDecompressorRejectsBytesBeforeZlibTrailer(t *testing.T) {
	payload := []byte("trailer must follow DEFLATE immediately")
	compressed := zlibCompress(t, payload)

	// Insert garbage after the DEFLATE stream while preserving its valid
	// Adler-32 trailer as the final four bytes. The trailer belongs directly
	// after DEFLATE, so this is not a valid zlib stream.
	bad := append([]byte(nil), compressed[:len(compressed)-4]...)
	bad = append(bad, 0xde, 0xad, 0xbe, 0xef)
	bad = append(bad, compressed[len(compressed)-4:]...)

	for _, skipChecksum := range []bool{false, true} {
		t.Run(fmt.Sprintf("skip_checksum=%t", skipChecksum), func(t *testing.T) {
			dec := osmbr.Decompressor{SkipChecksum: skipChecksum}
			if _, err := dec.Decompress(zlibBlob(len(payload), bad)); err == nil {
				t.Fatal("zlib stream with bytes before its trailer was accepted")
			}
		})
	}
}

func TestDecompressorRejectsWrongWireType(t *testing.T) {
	payload := []byte("valid compressed payload")
	// Blob.raw_size is a varint field, but encode it as an empty
	// length-delimited field. This used to be interpreted as the value zero.
	blob := append(pbLenDelim(2, nil), pbLenDelim(3, zlibCompress(t, payload))...)

	var dec osmbr.Decompressor
	if _, err := dec.Decompress(blob); err == nil {
		t.Fatal("length-delimited Blob.raw_size was accepted")
	}
}

// TestDecompressorCatchesStoredBlockCorruption is the case that justifies
// verifying by default. A flipped bit inside a stored (uncompressed) DEFLATE
// block leaves the stream structurally valid and exactly raw_size bytes long,
// so inflating and the length check both pass it through; only the Adler-32
// trailer notices.
func TestDecompressorCatchesStoredBlockCorruption(t *testing.T) {
	payload := []byte("the quick brown fox jumps over the lazy dog!!!!!")

	var b bytes.Buffer
	zw, err := zlib.NewWriterLevel(&b, flate.NoCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	bad := append([]byte(nil), b.Bytes()...)
	bad[len(bad)-8] ^= 0x20 // inside the stored literal data
	blob := zlibBlob(len(payload), bad)

	var dec osmbr.Decompressor
	if _, err := dec.Decompress(blob); err == nil {
		t.Fatal("corrupted stored block was accepted by default")
	} else if !strings.Contains(err.Error(), "Adler-32") {
		t.Errorf("error %q does not mention Adler-32", err)
	}

	// With the check off it is returned silently, corrupted.
	skip := osmbr.Decompressor{SkipChecksum: true}
	got, err := skip.Decompress(blob)
	if err != nil {
		t.Fatalf("Decompress with SkipChecksum: %v", err)
	}
	if bytes.Equal(got, payload) {
		t.Fatal("test no longer corrupts the payload; pick a different byte")
	}
}

func TestDecompressorRejectsBadZlibHeader(t *testing.T) {
	valid := zlibCompress(t, []byte("payload"))
	cases := []struct {
		name    string
		mutate  func([]byte) []byte
		wantSub string
	}{
		{"too short", func([]byte) []byte { return []byte{0x78, 0x9c, 0x01} }, "too short"},
		{"bad method", func(b []byte) []byte {
			out := append([]byte(nil), b...)
			out[0] = 0x79 // method 9, and the checksum no longer holds either
			return out
		}, "zlib"},
		{"bad window size", func(b []byte) []byte {
			out := append([]byte(nil), b...)
			out[0] = 0x88 // window bits 8 -> 32 KiB+, past the zlib maximum
			return out
		}, "window"},
		{"bad header checksum", func(b []byte) []byte {
			out := append([]byte(nil), b...)
			out[1] ^= 0x01
			return out
		}, "zlib header"},
		{"preset dictionary", func(b []byte) []byte {
			out := append([]byte(nil), b...)
			out[1] = 0x20 | (out[1] & 0x1f)
			// Re-satisfy (CMF<<8|FLG) % 31 == 0 so we reach the FDICT check.
			for i := 0; i < 32; i++ {
				if (uint(out[0])<<8|uint(out[1]&0xe0|byte(i)))%31 == 0 {
					out[1] = out[1]&0xe0 | byte(i)
					break
				}
			}
			return out
		}, "dictionary"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var dec osmbr.Decompressor
			_, err := dec.Decompress(zlibBlob(7, tc.mutate(valid)))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not mention %q", err, tc.wantSub)
			}
		})
	}
}

// TestDecompressorCapsUnsizedOutput guards the read-until-EOF branch against a
// decompression bomb: without raw_size there is nothing else bounding output.
func TestDecompressorCapsUnsizedOutput(t *testing.T) {
	const overLimit = 32*1024*1024 + 1
	blob := zlibBlob(-1, zlibCompress(t, make([]byte, overLimit)))

	var dec osmbr.Decompressor
	_, err := dec.Decompress(blob)
	if err == nil {
		t.Fatal("expected an error for output past the 32 MiB Blob limit")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error %q does not mention the size limit", err)
	}
}

func TestDecompressorNoAllocAfterWarmup(t *testing.T) {
	payload := bytes.Repeat([]byte("steady-state-"), 500)
	blob := zlibBlob(len(payload), zlibCompress(t, payload))

	var dec osmbr.Decompressor
	if _, err := dec.Decompress(blob); err != nil { // warm up
		t.Fatal(err)
	}
	got := testing.AllocsPerRun(20, func() {
		if _, err := dec.Decompress(blob); err != nil {
			t.Fatal(err)
		}
	})
	if got != 0 {
		t.Errorf("allocs per Decompress = %v, want 0", got)
	}
}

// TestDecompressorRejectsOverlongStream covers the exact-length check: a blob
// whose stream inflates past raw_size must fail even with checksums off.
func TestDecompressorRejectsOverlongStream(t *testing.T) {
	payload := []byte("the stream is longer than raw_size claims")
	blob := zlibBlob(len(payload)-5, zlibCompress(t, payload))

	var dec osmbr.Decompressor
	_, err := dec.Decompress(blob)
	if err == nil {
		t.Fatal("expected an error when the stream outruns raw_size")
	}
	if !strings.Contains(err.Error(), "raw_size") {
		t.Errorf("error %q does not mention raw_size", err)
	}

	// The decompressor must still work afterwards.
	good := zlibBlob(len(payload), zlibCompress(t, payload))
	got, err := dec.Decompress(good)
	if err != nil {
		t.Fatalf("Decompress after error: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("got %q, want %q", got, payload)
	}
}
