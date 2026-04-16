package osmbr

import (
	"bytes"
	"fmt"
	"io"

	"github.com/klauspost/compress/zlib"
	"github.com/paulmach/protoscan"
)

// Decompressor parses and decompresses raw PBF Blob messages.
// Allocate one per goroutine and reuse across blocks to avoid
// per-block allocations.
//
// Decompressor is not safe for concurrent use.
type Decompressor struct {
	brReader bytes.Reader
	zlibR    io.ReadCloser
	buf      []byte
}

// Decompress parses a raw Blob protobuf message and returns the
// decompressed payload. The returned slice is valid until the next
// call to Decompress.
func (d *Decompressor) Decompress(blob []byte) ([]byte, error) {
	var (
		rawData  []byte
		zlibData []byte
		rawSize  int
		hasRaw   bool
		hasZlib  bool
		msg      protoscan.Message
	)
	msg.Reset(blob)
	for msg.Next() {
		switch msg.FieldNumber() {
		case 1: // raw
			b, err := msg.Bytes()
			if err != nil {
				return nil, fmt.Errorf("osmbr: Blob.raw: %w", err)
			}
			rawData = b
			hasRaw = true
		case 2: // raw_size
			n, err := msg.Int32()
			if err != nil {
				return nil, fmt.Errorf("osmbr: Blob.raw_size: %w", err)
			}
			if n < 0 || n > maxBlobSize {
				return nil, fmt.Errorf("osmbr: invalid Blob.raw_size: %d", n)
			}
			rawSize = int(n)
		case 3: // zlib_data
			b, err := msg.Bytes()
			if err != nil {
				return nil, fmt.Errorf("osmbr: Blob.zlib_data: %w", err)
			}
			zlibData = b
			hasZlib = true
		case 4: // lzma_data
			return nil, fmt.Errorf("osmbr: unsupported Blob compression: lzma")
		case 5: // OBSOLETE_bzip2_data
			return nil, fmt.Errorf("osmbr: unsupported Blob compression: bzip2 (obsolete)")
		case 6: // lz4_data
			return nil, fmt.Errorf("osmbr: unsupported Blob compression: lz4")
		case 7: // zstd_data
			return nil, fmt.Errorf("osmbr: unsupported Blob compression: zstd")
		default:
			msg.Skip()
		}
	}
	if err := msg.Err(); err != nil {
		return nil, fmt.Errorf("osmbr: Blob: %w", err)
	}

	switch {
	case hasRaw:
		return rawData, nil
	case hasZlib:
		return d.decompress(zlibData, rawSize)
	default:
		return nil, fmt.Errorf("osmbr: Blob contains no data")
	}
}

func (d *Decompressor) decompress(data []byte, rawSize int) ([]byte, error) {
	d.brReader.Reset(data)

	var err error
	if d.zlibR == nil {
		d.zlibR, err = zlib.NewReader(&d.brReader)
		if err != nil {
			return nil, fmt.Errorf("osmbr: zlib.NewReader: %w", err)
		}
	} else if err = d.zlibR.(zlib.Resetter).Reset(&d.brReader, nil); err != nil {
		d.zlibR = nil
		return nil, fmt.Errorf("osmbr: zlib Reset: %w", err)
	}

	if rawSize > 0 {
		if cap(d.buf) < rawSize {
			d.buf = make([]byte, rawSize)
		} else {
			d.buf = d.buf[:rawSize]
		}
		_, err = io.ReadFull(d.zlibR, d.buf)
	} else {
		d.buf = d.buf[:0]
		d.buf, err = io.ReadAll(d.zlibR)
	}

	if err != nil {
		d.zlibR = nil
		return nil, fmt.Errorf("osmbr: decompress: %w", err)
	}

	return d.buf, nil
}
