package osmbr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/paulmach/protoscan"
)

// PBF format limits per the OSM PBF spec.
// https://wiki.openstreetmap.org/wiki/PBF_Format
const (
	maxBlobHeaderSize = 64 * 1024        // 64 KiB
	maxBlobSize       = 32 * 1024 * 1024 // 32 MiB (compressed and uncompressed)
)

var (
	bOSMHeader = []byte("OSMHeader")
	bOSMData   = []byte("OSMData")
)

// BlockReader reads PBF FileBlocks from an io.Reader.
// Call Next to advance, then Type and Blob to access the current block.
// Blob returns the raw Blob protobuf message; use a Decompressor to
// decompress it.
//
// BlockReader is not safe for concurrent use.
type BlockReader struct {
	r         io.Reader
	lenBuf    [4]byte
	headerBuf []byte
	blobBuf   []byte
	blockType string
	offset    int64 // byte offset where current block starts
	pos       int64 // running read position
	err       error
}

// NewBlockReader returns a BlockReader that reads PBF blocks from r.
func NewBlockReader(r io.Reader) *BlockReader {
	return &BlockReader{
		r:         r,
		headerBuf: make([]byte, 0, 256),
		blobBuf:   make([]byte, 0, 65536),
	}
}

// Next reads the next FileBlock. Returns false on EOF or error.
// Call Err to distinguish between them.
func (br *BlockReader) Next() bool {
	br.offset = br.pos

	_, err := io.ReadFull(br.r, br.lenBuf[:])
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return false
	}
	if err != nil {
		br.err = err
		return false
	}
	br.pos += 4

	headerLen := binary.BigEndian.Uint32(br.lenBuf[:])
	if headerLen > maxBlobHeaderSize {
		br.err = fmt.Errorf("osmbr: BlobHeader too large: %d bytes", headerLen)
		return false
	}

	if cap(br.headerBuf) < int(headerLen) {
		br.headerBuf = make([]byte, headerLen)
	} else {
		br.headerBuf = br.headerBuf[:headerLen]
	}
	if _, err = io.ReadFull(br.r, br.headerBuf); err != nil {
		br.err = err
		return false
	}
	br.pos += int64(headerLen)

	// Scan BlobHeader: field 1=type (string), field 3=datasize (int32)
	var (
		dataSize int64
		hMsg     protoscan.Message
	)
	br.blockType = ""
	hMsg.Reset(br.headerBuf)
	for hMsg.Next() {
		switch hMsg.FieldNumber() {
		case 1:
			b, err := hMsg.Bytes()
			if err != nil {
				br.err = fmt.Errorf("osmbr: BlobHeader.type: %w", err)
				return false
			}
			switch {
			case bytes.Equal(b, bOSMHeader):
				br.blockType = "OSMHeader"
			case bytes.Equal(b, bOSMData):
				br.blockType = "OSMData"
			default:
				br.blockType = string(b)
			}
		case 3:
			v, err := hMsg.Int64()
			if err != nil {
				br.err = fmt.Errorf("osmbr: BlobHeader.datasize: %w", err)
				return false
			}
			dataSize = v
		default:
			hMsg.Skip()
		}
	}
	if err := hMsg.Err(); err != nil {
		br.err = fmt.Errorf("osmbr: BlobHeader: %w", err)
		return false
	}
	if dataSize <= 0 || dataSize > maxBlobSize {
		br.err = fmt.Errorf("osmbr: invalid BlobHeader.datasize: %d", dataSize)
		return false
	}

	// Read Blob bytes
	if int64(cap(br.blobBuf)) < dataSize {
		br.blobBuf = make([]byte, dataSize)
	} else {
		br.blobBuf = br.blobBuf[:dataSize]
	}
	if _, err = io.ReadFull(br.r, br.blobBuf); err != nil {
		br.err = err
		return false
	}
	br.pos += dataSize

	return true
}

// Err returns the first non-EOF error encountered.
func (br *BlockReader) Err() error { return br.err }

// Offset returns the byte offset where the current block starts in the
// underlying reader. Use with io.Seeker to re-read a specific block later.
func (br *BlockReader) Offset() int64 { return br.offset }

// Type returns the block type ("OSMHeader" or "OSMData").
func (br *BlockReader) Type() string { return br.blockType }

// Blob returns the raw Blob protobuf message bytes for the current block.
// Use a Decompressor to decompress them.
// Valid only until the next call to Next.
func (br *BlockReader) Blob() []byte { return br.blobBuf }
