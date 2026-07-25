package osmbr

import "fmt"

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
	var m msg
	m.reset(data)
	for m.next() {
		switch m.field {
		case 1: // bbox
			bboxData := m.bytes()
			if m.err != nil {
				return h, fmt.Errorf("osmbr: Header.bbox: %w", m.err)
			}
			bb, err := decodeHeaderBBox(bboxData)
			if err != nil {
				return h, err
			}
			h.BBox = bb
		case 4: // required_features
			b := m.bytes()
			if m.err != nil {
				return h, fmt.Errorf("osmbr: Header.required_features: %w", m.err)
			}
			h.RequiredFeatures = append(h.RequiredFeatures, string(b))
		case 5: // optional_features
			b := m.bytes()
			if m.err != nil {
				return h, fmt.Errorf("osmbr: Header.optional_features: %w", m.err)
			}
			h.OptionalFeatures = append(h.OptionalFeatures, string(b))
		case 16: // writingprogram
			b := m.bytes()
			if m.err != nil {
				return h, fmt.Errorf("osmbr: Header.writingprogram: %w", m.err)
			}
			h.WritingProgram = string(b)
		case 17: // source
			b := m.bytes()
			if m.err != nil {
				return h, fmt.Errorf("osmbr: Header.source: %w", m.err)
			}
			h.Source = string(b)
		case 32: // osmosis_replication_timestamp
			v := m.int64()
			h.ReplicationTimestamp = v
		case 33: // osmosis_replication_sequence_number
			v := m.int64()
			h.ReplicationSequenceNumber = v
		case 34: // osmosis_replication_base_url
			b := m.bytes()
			if m.err != nil {
				return h, fmt.Errorf("osmbr: Header.osmosis_replication_base_url: %w", m.err)
			}
			h.ReplicationBaseURL = string(b)
		default:
			m.skip()
		}
	}
	if m.err != nil {
		return h, fmt.Errorf("osmbr: Header: %w", m.err)
	}
	return h, nil
}

func decodeHeaderBBox(data []byte) (HeaderBBox, error) {
	var bb HeaderBBox
	var m msg
	m.reset(data)
	for m.next() {
		switch m.field {
		case 1:
			bb.Left = m.sint64()
		case 2:
			bb.Right = m.sint64()
		case 3:
			bb.Top = m.sint64()
		case 4:
			bb.Bottom = m.sint64()
		default:
			m.skip()
		}
	}
	if m.err != nil {
		return bb, fmt.Errorf("osmbr: HeaderBBox: %w", m.err)
	}
	return bb, nil
}
