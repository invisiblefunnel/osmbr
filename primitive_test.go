package osmbr_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/invisiblefunnel/osmbr"
)

// primitiveBlockBytes returns a PrimitiveBlock encoded with the given
// stringtable entries (field 1). Additional raw bytes are appended verbatim,
// letting callers tack on primitivegroup / granularity / offset fields.
func primitiveBlockBytes(stringTable [][]byte, extras ...byte) []byte {
	var st []byte
	for _, s := range stringTable {
		st = append(st, pbLenDelim(1, s)...)
	}
	out := pbLenDelim(1, st)
	return append(out, extras...)
}

func TestPrimitiveBlockDefaults(t *testing.T) {
	// Bare block with only a one-entry stringtable (and no 17/18/19/20 fields).
	block := primitiveBlockBytes([][]byte{nil})

	var pb osmbr.PrimitiveBlock
	if err := pb.DecodeFrom(block); err != nil {
		t.Fatalf("DecodeFrom: %v", err)
	}
	if pb.Granularity != 100 {
		t.Errorf("Granularity = %d, want 100", pb.Granularity)
	}
	if pb.DateGranularity != 1000 {
		t.Errorf("DateGranularity = %d, want 1000", pb.DateGranularity)
	}
	if pb.LatOffset != 0 {
		t.Errorf("LatOffset = %d, want 0", pb.LatOffset)
	}
	if pb.LonOffset != 0 {
		t.Errorf("LonOffset = %d, want 0", pb.LonOffset)
	}
}

func TestPrimitiveBlockExplicitScaling(t *testing.T) {
	// Non-default granularity and offsets.
	extras := pbVarintField(17, 200)                   // granularity
	extras = append(extras, pbVarintField(18, 500)...) // date_granularity
	extras = append(extras, pbVarintField(19, 42)...)  // lat_offset
	extras = append(extras, pbVarintField(20, 84)...)  // lon_offset
	block := primitiveBlockBytes([][]byte{nil}, extras...)

	var pb osmbr.PrimitiveBlock
	if err := pb.DecodeFrom(block); err != nil {
		t.Fatalf("DecodeFrom: %v", err)
	}
	if pb.Granularity != 200 {
		t.Errorf("Granularity = %d, want 200", pb.Granularity)
	}
	if pb.DateGranularity != 500 {
		t.Errorf("DateGranularity = %d, want 500", pb.DateGranularity)
	}
	if pb.LatOffset != 42 {
		t.Errorf("LatOffset = %d, want 42", pb.LatOffset)
	}
	if pb.LonOffset != 84 {
		t.Errorf("LonOffset = %d, want 84", pb.LonOffset)
	}
}

func TestPrimitiveBlockStringTable(t *testing.T) {
	entries := [][]byte{[]byte(""), []byte("highway"), []byte("residential")}
	block := primitiveBlockBytes(entries)

	var pb osmbr.PrimitiveBlock
	if err := pb.DecodeFrom(block); err != nil {
		t.Fatalf("DecodeFrom: %v", err)
	}
	if got, want := pb.NumStrings(), len(entries); got != want {
		t.Fatalf("NumStrings = %d, want %d", got, want)
	}
	for i, want := range entries {
		if got := pb.String(i); !bytes.Equal(got, want) {
			t.Errorf("String(%d) = %q, want %q", i, got, want)
		}
	}
}

// TestPrimitiveBlockReuse confirms that a second DecodeFrom on the same
// PrimitiveBlock does not leak stringtable entries from the first block.
func TestPrimitiveBlockReuse(t *testing.T) {
	first := primitiveBlockBytes([][]byte{[]byte("a"), []byte("b"), []byte("c")})
	second := primitiveBlockBytes([][]byte{[]byte("x")})

	var pb osmbr.PrimitiveBlock
	if err := pb.DecodeFrom(first); err != nil {
		t.Fatalf("DecodeFrom(first): %v", err)
	}
	if pb.NumStrings() != 3 {
		t.Fatalf("NumStrings after first = %d, want 3", pb.NumStrings())
	}

	if err := pb.DecodeFrom(second); err != nil {
		t.Fatalf("DecodeFrom(second): %v", err)
	}
	if pb.NumStrings() != 1 {
		t.Fatalf("NumStrings after second = %d, want 1", pb.NumStrings())
	}
	if !bytes.Equal(pb.String(0), []byte("x")) {
		t.Errorf("String(0) = %q, want %q", pb.String(0), "x")
	}
}

func TestPrimitiveBlockUnknownField(t *testing.T) {
	// Append an unknown varint field (number 42). Should be skipped silently.
	extras := pbVarintField(42, 12345)
	block := primitiveBlockBytes([][]byte{nil}, extras...)

	var pb osmbr.PrimitiveBlock
	if err := pb.DecodeFrom(block); err != nil {
		t.Errorf("DecodeFrom with unknown field: %v", err)
	}
}

func TestPrimitiveBlockTruncatedStringTable(t *testing.T) {
	// Length-prefix claims 10 bytes but only 2 follow.
	trunc := append(pbTag(1, 2), 10, 'a', 'b')

	var pb osmbr.PrimitiveBlock
	err := pb.DecodeFrom(trunc)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "stringtable") && !strings.Contains(err.Error(), "PrimitiveBlock") {
		t.Errorf("error %q lacks context", err)
	}
}
