package osmbr_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/invisiblefunnel/osmbr"
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
// (field 3). If rawSize < 0, the raw_size field is omitted (triggers the
// io.ReadAll branch in Decompressor.decompress).
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
	// Exercise the io.ReadAll branch (raw_size absent → field 2 not set).
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
