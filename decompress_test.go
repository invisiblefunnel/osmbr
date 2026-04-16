package osmbr_test

import (
	"strings"
	"testing"

	"github.com/invisiblefunnel/osmbr"
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
