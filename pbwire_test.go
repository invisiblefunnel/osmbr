package osmbr_test

// Test-only helpers for building synthetic protobuf wire bytes.
// The basic encoders (pbVarint, pbTag, pbLenDelim, pbVarintField) live in
// decompress_test.go; pbZigzag and pbSint64Field live in node_test.go.
// This file adds packed-repeated encoders used across several tests.

// pbPackedSint64 encodes a packed repeated sint64 field (zig-zag varints).
func pbPackedSint64(fieldNumber int, values []int64) []byte {
	var payload []byte
	for _, v := range values {
		payload = append(payload, pbVarint(pbZigzag(v))...)
	}
	return pbLenDelim(fieldNumber, payload)
}

// pbPackedSint32 encodes a packed repeated sint32 field.
func pbPackedSint32(fieldNumber int, values []int32) []byte {
	var payload []byte
	for _, v := range values {
		payload = append(payload, pbVarint(pbZigzag(int64(v)))...)
	}
	return pbLenDelim(fieldNumber, payload)
}

// pbPackedUint32 encodes a packed repeated uint32 field (plain varints).
func pbPackedUint32(fieldNumber int, values []uint32) []byte {
	var payload []byte
	for _, v := range values {
		payload = append(payload, pbVarint(uint64(v))...)
	}
	return pbLenDelim(fieldNumber, payload)
}

// pbPackedInt32 encodes a packed repeated int32 field.
// Negative values are sign-extended to 64 bits (10-byte varints).
func pbPackedInt32(fieldNumber int, values []int32) []byte {
	var payload []byte
	for _, v := range values {
		payload = append(payload, pbVarint(uint64(int64(v)))...)
	}
	return pbLenDelim(fieldNumber, payload)
}

// pbPackedBool encodes a packed repeated bool field.
func pbPackedBool(fieldNumber int, values []bool) []byte {
	var payload []byte
	for _, v := range values {
		if v {
			payload = append(payload, 1)
		} else {
			payload = append(payload, 0)
		}
	}
	return pbLenDelim(fieldNumber, payload)
}
