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
	if br.Next() {
		t.Fatal("Next on empty input should return false")
	}
	if err := br.Err(); err != nil {
		t.Errorf("Err on empty input = %v, want nil", err)
	}
}

func TestBlockReaderTruncatedHeaderLength(t *testing.T) {
	// Only 2 bytes — not enough for the 4-byte length prefix.
	br := osmbr.NewBlockReader(bytes.NewReader([]byte{0, 0}))
	if br.Next() {
		t.Fatal("Next on partial length prefix should return false")
	}
	if err := br.Err(); err != nil {
		t.Errorf("Err on partial length prefix = %v, want nil (clean EOF)", err)
	}
}

func TestBlockReaderTruncatedHeader(t *testing.T) {
	// Length prefix says 100 bytes of header but only 5 bytes follow.
	data := []byte{0, 0, 0, 100, 1, 2, 3, 4, 5}
	br := osmbr.NewBlockReader(bytes.NewReader(data))
	if br.Next() {
		t.Fatal("Next on truncated header should return false")
	}
	if err := br.Err(); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestBlockReaderTruncatedBlob(t *testing.T) {
	// Valid header announcing 200 bytes of blob, but only 10 bytes follow.
	frame := pbfFrame("OSMData", make([]byte, 200))
	br := osmbr.NewBlockReader(bytes.NewReader(frame[:len(frame)-190]))
	if br.Next() {
		t.Fatal("Next on truncated blob should return false")
	}
	if err := br.Err(); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestBlockReaderOversizedHeader(t *testing.T) {
	// Length prefix exceeds the spec maximum (64 KiB).
	data := []byte{0x00, 0x01, 0x00, 0x01} // 65537
	br := osmbr.NewBlockReader(bytes.NewReader(data))
	if br.Next() {
		t.Fatal("Next on oversized header should return false")
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
			if br.Next() {
				t.Fatal("Next with invalid datasize should return false")
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
	if !br.Next() {
		t.Fatalf("Next returned false: %v", br.Err())
	}
	if got := br.Type(); got != "CustomType" {
		t.Errorf("Type = %q, want %q", got, "CustomType")
	}
}

func TestBlockReaderRoundTripSyntheticFrame(t *testing.T) {
	blob := pbLenDelim(1, []byte("payload")) // raw blob
	frame := pbfFrame("OSMData", blob)
	br := osmbr.NewBlockReader(bytes.NewReader(frame))
	if !br.Next() {
		t.Fatalf("Next returned false: %v", br.Err())
	}
	if br.Type() != "OSMData" {
		t.Errorf("Type = %q, want %q", br.Type(), "OSMData")
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
