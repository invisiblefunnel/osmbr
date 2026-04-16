package osmbr

import (
	"fmt"

	"github.com/paulmach/protoscan"
)

// Header holds the decoded contents of an OSMHeader block.
type Header struct {
	// BBox is the bounding box of the data in nanodegrees.
	// Left and Right are longitude; Top and Bottom are latitude.
	BBox HeaderBBox

	// RequiredFeatures lists features a parser must support (e.g. "OsmSchema-V0.6", "DenseNodes").
	RequiredFeatures []string

	// OptionalFeatures lists features a parser may optionally handle (e.g. "Sort.Type_then_ID").
	OptionalFeatures []string

	// WritingProgram identifies the tool that created the file (e.g. "osmium/1.16.0").
	WritingProgram string

	// Source identifies the data source.
	Source string

	// ReplicationTimestamp is seconds since Unix epoch for the replication state.
	ReplicationTimestamp int64

	// ReplicationSequenceNumber is the replication sequence number.
	ReplicationSequenceNumber int64

	// ReplicationBaseURL is the base URL for replication diff files.
	ReplicationBaseURL string
}

// HeaderBBox holds bounding box coordinates in nanodegrees.
type HeaderBBox struct {
	Left, Right, Top, Bottom int64
}

// DecodeHeader decodes a decompressed OSMHeader block.
func DecodeHeader(data []byte) (Header, error) {
	var h Header
	var msg protoscan.Message
	msg.Reset(data)
	for msg.Next() {
		var err error
		switch msg.FieldNumber() {
		case 1: // bbox
			bboxData, e := msg.MessageData()
			if e != nil {
				return h, fmt.Errorf("osmbr: Header.bbox: %w", e)
			}
			h.BBox, err = decodeHeaderBBox(bboxData)
		case 4: // required_features
			b, e := msg.Bytes()
			if e != nil {
				return h, fmt.Errorf("osmbr: Header.required_features: %w", e)
			}
			h.RequiredFeatures = append(h.RequiredFeatures, string(b))
		case 5: // optional_features
			b, e := msg.Bytes()
			if e != nil {
				return h, fmt.Errorf("osmbr: Header.optional_features: %w", e)
			}
			h.OptionalFeatures = append(h.OptionalFeatures, string(b))
		case 16: // writingprogram
			b, e := msg.Bytes()
			if e != nil {
				return h, fmt.Errorf("osmbr: Header.writingprogram: %w", e)
			}
			h.WritingProgram = string(b)
		case 17: // source
			b, e := msg.Bytes()
			if e != nil {
				return h, fmt.Errorf("osmbr: Header.source: %w", e)
			}
			h.Source = string(b)
		case 32: // osmosis_replication_timestamp
			h.ReplicationTimestamp, err = msg.Int64()
		case 33: // osmosis_replication_sequence_number
			h.ReplicationSequenceNumber, err = msg.Int64()
		case 34: // osmosis_replication_base_url
			b, e := msg.Bytes()
			if e != nil {
				return h, fmt.Errorf("osmbr: Header.replication_base_url: %w", e)
			}
			h.ReplicationBaseURL = string(b)
		default:
			msg.Skip()
		}
		if err != nil {
			return h, fmt.Errorf("osmbr: Header field %d: %w", msg.FieldNumber(), err)
		}
	}
	if err := msg.Err(); err != nil {
		return h, fmt.Errorf("osmbr: Header: %w", err)
	}
	return h, nil
}

func decodeHeaderBBox(data []byte) (HeaderBBox, error) {
	var bb HeaderBBox
	var msg protoscan.Message
	msg.Reset(data)
	for msg.Next() {
		var err error
		switch msg.FieldNumber() {
		case 1:
			bb.Left, err = msg.Sint64()
		case 2:
			bb.Right, err = msg.Sint64()
		case 3:
			bb.Top, err = msg.Sint64()
		case 4:
			bb.Bottom, err = msg.Sint64()
		default:
			msg.Skip()
		}
		if err != nil {
			return bb, fmt.Errorf("osmbr: HeaderBBox field %d: %w", msg.FieldNumber(), err)
		}
	}
	return bb, msg.Err()
}
