package osmbr

import (
	"bytes"
	"encoding/binary"
	"errors"
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

// blobHeaderScratch sizes the inline BlobHeader buffer. Real headers carry a
// short type string and a datasize varint (~14 bytes); anything larger falls
// back to a heap buffer, so a BlockReader never allocates in practice.
const blobHeaderScratch = 128

var (
	bOSMHeader = []byte("OSMHeader")
	bOSMData   = []byte("OSMData")
)

// BlockReader reads PBF FileBlocks from an io.Reader. The zero value is ready
// to use after Reset, so a BlockReader can be embedded in a caller-owned
// struct and reused without allocating.
//
// Call Next to advance and Blob to get the current block's raw Blob protobuf
// message, or NextInto to read into caller-owned storage. Type and Offset
// describe the current block. Use a Decompressor to decompress the blob.
//
// BlockReader is not safe for concurrent use.
type BlockReader struct {
	r         io.Reader
	blockType string
	offset    int64 // byte offset where current block starts
	pos       int64 // running read position
	err       error
	blobBuf   []byte // storage behind Blob
	hdrBuf    []byte // heap fallback for oversized BlobHeaders
	lenBuf    [4]byte
	hdrArr    [blobHeaderScratch]byte
}

// NewBlockReader returns a BlockReader that reads PBF blocks from r.
//
// Equivalent to declaring a BlockReader and calling Reset; use that form to
// keep the reader inside a struct you already own.
func NewBlockReader(r io.Reader) *BlockReader {
	return &BlockReader{r: r}
}

// Reset reuses br to read from r, preserving buffer capacities. Use this to
// walk many files with one BlockReader instead of allocating a new one per
// file.
func (br *BlockReader) Reset(r io.Reader) {
	br.r = r
	br.blockType = ""
	br.offset = 0
	br.pos = 0
	br.err = nil
	br.blobBuf = br.blobBuf[:0]
}

// Next reads the next FileBlock into br's own storage, which Blob then
// returns. It reports false on EOF or error; call Err to distinguish them.
//
// Use NextInto instead when the blob must outlive the next read, such as when
// handing blocks to worker goroutines.
func (br *BlockReader) Next() bool {
	blob, ok := br.NextInto(br.blobBuf[:0])
	br.blobBuf = blob
	return ok
}

// Blob returns the raw Blob protobuf message bytes read by the most recent
// call to Next. It is invalidated by the next call to Next or NextInto, and
// is empty once Next has returned false.
func (br *BlockReader) Blob() []byte { return br.blobBuf }

// NextInto reads the next FileBlock into dst, overwriting it, and returns the
// slice holding the raw Blob protobuf message. When cap(dst) is too small it
// allocates a larger slice instead, so the returned slice may have a different
// backing array than dst.
//
// It reports false on EOF or error, returning dst[:0] so a caller that pools
// buffers never loses one. Call Err to distinguish EOF from an error. After a
// successful call, Type and Offset describe the current block.
func (br *BlockReader) NextInto(dst []byte) ([]byte, bool) {
	br.offset = br.pos

	_, err := io.ReadFull(br.r, br.lenBuf[:])
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return dst[:0], false
	}
	if err != nil {
		br.err = fmt.Errorf("osmbr: reading BlobHeader length: %w", err)
		return dst[:0], false
	}
	br.pos += 4

	headerLen := binary.BigEndian.Uint32(br.lenBuf[:])
	if headerLen > maxBlobHeaderSize {
		br.err = fmt.Errorf("osmbr: BlobHeader too large: %d bytes", headerLen)
		return dst[:0], false
	}

	header := br.headerStorage(int(headerLen))
	if _, err = io.ReadFull(br.r, header); err != nil {
		br.err = fmt.Errorf("osmbr: reading BlobHeader: %w", err)
		return dst[:0], false
	}
	br.pos += int64(headerLen)

	dataSize, err := br.decodeBlobHeader(header)
	if err != nil {
		br.err = err
		return dst[:0], false
	}

	// Read Blob bytes
	blob := dst[:0]
	if cap(blob) < dataSize {
		blob = make([]byte, 0, dataSize)
	}
	blob = blob[:dataSize]
	if _, err = io.ReadFull(br.r, blob); err != nil {
		br.err = fmt.Errorf("osmbr: reading Blob: %w", err)
		return dst[:0], false
	}
	br.pos += int64(dataSize)

	return blob, true
}

// headerStorage returns an n-byte scratch slice for the BlobHeader, using the
// inline array when it fits.
func (br *BlockReader) headerStorage(n int) []byte {
	if n <= len(br.hdrArr) {
		return br.hdrArr[:n]
	}
	if cap(br.hdrBuf) < n {
		br.hdrBuf = make([]byte, n)
	}
	return br.hdrBuf[:n]
}

// decodeBlobHeader scans a BlobHeader message, setting br.blockType and
// returning the Blob's datasize.
func (br *BlockReader) decodeBlobHeader(header []byte) (int, error) {
	var (
		dataSize int64
		m        protoscan.Message
	)
	br.blockType = ""
	m.Reset(header)
	for m.Next() {
		switch m.FieldNumber() {
		case 1: // type (string)
			b, err := m.Bytes()
			if err != nil {
				return 0, fmt.Errorf("osmbr: BlobHeader.type: %w", err)
			}
			switch {
			case bytes.Equal(b, bOSMHeader):
				br.blockType = "OSMHeader"
			case bytes.Equal(b, bOSMData):
				br.blockType = "OSMData"
			default:
				br.blockType = string(b)
			}
		case 3: // datasize (int32)
			v, err := m.Int32()
			if err != nil {
				return 0, fmt.Errorf("osmbr: BlobHeader.datasize: %w", err)
			}
			dataSize = int64(v)
		default:
			m.Skip()
		}
	}
	if err := m.Err(); err != nil {
		return 0, fmt.Errorf("osmbr: BlobHeader: %w", err)
	}
	if dataSize <= 0 || dataSize > maxBlobSize {
		return 0, fmt.Errorf("osmbr: invalid BlobHeader.datasize: %d", dataSize)
	}
	return int(dataSize), nil
}

// Err returns the first non-EOF error encountered.
func (br *BlockReader) Err() error { return br.err }

// Offset returns the byte offset where the current block starts in the
// underlying reader. Use with io.Seeker to re-read a specific block later.
func (br *BlockReader) Offset() int64 { return br.offset }

// Type returns the block type ("OSMHeader" or "OSMData").
func (br *BlockReader) Type() string { return br.blockType }
