package osmbr_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/invisiblefunnel/osmbr"
)

// bboxBytes builds a HeaderBBox submessage body with the given sint64
// fields (left=1, right=2, top=3, bottom=4).
func bboxBytes(left, right, top, bottom int64) []byte {
	out := pbSint64Field(1, left)
	out = append(out, pbSint64Field(2, right)...)
	out = append(out, pbSint64Field(3, top)...)
	out = append(out, pbSint64Field(4, bottom)...)
	return out
}

func TestDecodeHeaderAllFields(t *testing.T) {
	var data []byte
	data = append(data, pbLenDelim(1, bboxBytes(-1, 2, 3, -4))...)
	data = append(data, pbLenDelim(4, []byte("OsmSchema-V0.6"))...)
	data = append(data, pbLenDelim(4, []byte("DenseNodes"))...)
	data = append(data, pbLenDelim(5, []byte("Sort.Type_then_ID"))...)
	data = append(data, pbLenDelim(16, []byte("osmbr-test"))...)
	data = append(data, pbLenDelim(17, []byte("example.org"))...)
	data = append(data, pbVarintField(32, 1700000000)...)
	data = append(data, pbVarintField(33, 12345)...)
	data = append(data, pbLenDelim(34, []byte("https://planet.example/replication"))...)

	h, err := osmbr.DecodeHeader(data)
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if h.BBox != (osmbr.HeaderBBox{Left: -1, Right: 2, Top: 3, Bottom: -4}) {
		t.Errorf("BBox = %+v", h.BBox)
	}
	if !slices.Equal(h.RequiredFeatures, []string{"OsmSchema-V0.6", "DenseNodes"}) {
		t.Errorf("RequiredFeatures = %v", h.RequiredFeatures)
	}
	if !slices.Equal(h.OptionalFeatures, []string{"Sort.Type_then_ID"}) {
		t.Errorf("OptionalFeatures = %v", h.OptionalFeatures)
	}
	if h.WritingProgram != "osmbr-test" {
		t.Errorf("WritingProgram = %q", h.WritingProgram)
	}
	if h.Source != "example.org" {
		t.Errorf("Source = %q", h.Source)
	}
	if h.ReplicationTimestamp != 1700000000 {
		t.Errorf("ReplicationTimestamp = %d", h.ReplicationTimestamp)
	}
	if h.ReplicationSequenceNumber != 12345 {
		t.Errorf("ReplicationSequenceNumber = %d", h.ReplicationSequenceNumber)
	}
	if h.ReplicationBaseURL != "https://planet.example/replication" {
		t.Errorf("ReplicationBaseURL = %q", h.ReplicationBaseURL)
	}
}

func TestDecodeHeaderMinimal(t *testing.T) {
	// Only required_features present — the minimum legal OSMHeader.
	data := pbLenDelim(4, []byte("OsmSchema-V0.6"))
	h, err := osmbr.DecodeHeader(data)
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if !slices.Equal(h.RequiredFeatures, []string{"OsmSchema-V0.6"}) {
		t.Errorf("RequiredFeatures = %v", h.RequiredFeatures)
	}
	if h.WritingProgram != "" || h.Source != "" {
		t.Errorf("expected empty optional strings, got WP=%q Source=%q", h.WritingProgram, h.Source)
	}
	if h.ReplicationTimestamp != 0 || h.ReplicationSequenceNumber != 0 {
		t.Errorf("expected zero replication fields")
	}
}

func TestDecodeHeaderUnknownFieldsIgnored(t *testing.T) {
	data := pbLenDelim(4, []byte("OsmSchema-V0.6"))
	data = append(data, pbVarintField(99, 42)...) // unknown varint field
	data = append(data, pbLenDelim(100, []byte("trailer"))...)

	if _, err := osmbr.DecodeHeader(data); err != nil {
		t.Errorf("DecodeHeader with unknown fields: %v", err)
	}
}

func TestDecodeHeaderMalformedBBox(t *testing.T) {
	// bbox length-prefix claims 20 bytes but only 2 follow.
	trunc := append(pbTag(1, 2), 20, 0, 0)
	_, err := osmbr.DecodeHeader(trunc)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "Header") {
		t.Errorf("error %q lacks Header context", err)
	}
}

func TestDecodeHeaderEmptyInput(t *testing.T) {
	h, err := osmbr.DecodeHeader(nil)
	if err != nil {
		t.Errorf("DecodeHeader(nil): %v", err)
	}
	if h.BBox != (osmbr.HeaderBBox{}) {
		t.Errorf("BBox = %+v, want zero", h.BBox)
	}
}
