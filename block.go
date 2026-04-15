package osmbr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/klauspost/compress/zlib"
	"github.com/paulmach/protoscan"
)

var (
	bOSMHeader = []byte("OSMHeader")
	bOSMData   = []byte("OSMData")
)

// BlockReader reads and decompresses PBF FileBlocks from an io.Reader.
// Call Next to advance, then Type and Data to access the current block.
// Data is only valid until the next call to Next.
//
// BlockReader is not safe for concurrent use.
type BlockReader struct {
	r         io.Reader
	lenBuf    [4]byte
	headerBuf []byte
	blobBuf   []byte
	rawBuf    []byte
	brReader  bytes.Reader
	zlibR     io.ReadCloser // reused zlib reader; nil until first zlib block
	blockType string
	blockData []byte
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
	if headerLen > 65536 {
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
	if dataSize <= 0 || dataSize > 33554432 {
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

	// Scan Blob: fields can arrive in any order, collect all then act
	var (
		rawData  []byte
		zlibData []byte
		rawSize  int
		hasRaw   bool
		hasZlib  bool
		bMsg     protoscan.Message
	)
	bMsg.Reset(br.blobBuf)
	for bMsg.Next() {
		switch bMsg.FieldNumber() {
		case 1: // raw
			d, err := bMsg.Bytes()
			if err != nil {
				br.err = fmt.Errorf("osmbr: Blob.raw: %w", err)
				return false
			}
			rawData = d
			hasRaw = true
		case 2: // raw_size
			n, err := bMsg.Int64()
			if err != nil {
				br.err = fmt.Errorf("osmbr: Blob.raw_size: %w", err)
				return false
			}
			rawSize = int(n)
		case 3: // zlib_data
			d, err := bMsg.Bytes()
			if err != nil {
				br.err = fmt.Errorf("osmbr: Blob.zlib_data: %w", err)
				return false
			}
			zlibData = d
			hasZlib = true
		default:
			fn := bMsg.FieldNumber()
			bMsg.Skip()
			if fn == 4 || fn == 5 {
				br.err = fmt.Errorf("osmbr: unsupported Blob compression (field %d)", fn)
				return false
			}
		}
	}
	if err := bMsg.Err(); err != nil {
		br.err = fmt.Errorf("osmbr: Blob: %w", err)
		return false
	}

	switch {
	case hasRaw:
		br.blockData = rawData
	case hasZlib:
		if err := br.decompress(zlibData, rawSize); err != nil {
			br.err = err
			return false
		}
	default:
		br.err = fmt.Errorf("osmbr: Blob contains no data")
		return false
	}

	return true
}

func (br *BlockReader) decompress(data []byte, rawSize int) error {
	br.brReader.Reset(data)

	var err error
	if br.zlibR == nil {
		br.zlibR, err = zlib.NewReader(&br.brReader)
		if err != nil {
			return fmt.Errorf("osmbr: zlib.NewReader: %w", err)
		}
	} else if err = br.zlibR.(zlib.Resetter).Reset(&br.brReader, nil); err != nil {
		br.zlibR = nil
		return fmt.Errorf("osmbr: zlib Reset: %w", err)
	}

	if rawSize > 0 {
		if cap(br.rawBuf) < rawSize {
			br.rawBuf = make([]byte, rawSize)
		} else {
			br.rawBuf = br.rawBuf[:rawSize]
		}
		_, err = io.ReadFull(br.zlibR, br.rawBuf)
	} else {
		br.rawBuf = br.rawBuf[:0]
		br.rawBuf, err = io.ReadAll(br.zlibR)
	}

	if err != nil {
		br.zlibR = nil
		return fmt.Errorf("osmbr: decompress: %w", err)
	}

	br.blockData = br.rawBuf
	return nil
}

// Err returns the first non-EOF error encountered.
func (br *BlockReader) Err() error { return br.err }

// Offset returns the byte offset where the current block starts in the
// underlying reader. Use with io.Seeker to re-read a specific block later.
func (br *BlockReader) Offset() int64 { return br.offset }

// Type returns the block type ("OSMHeader" or "OSMData").
func (br *BlockReader) Type() string { return br.blockType }

// Data returns the decompressed proto bytes of the current block.
// Valid only until the next call to Next.
func (br *BlockReader) Data() []byte { return br.blockData }
