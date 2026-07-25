package osmbr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/adler32"
	"io"

	"github.com/klauspost/compress/flate"
)

// Decompressor parses and decompresses raw PBF Blob messages.
// Allocate one per goroutine and reuse across blocks to avoid
// per-block allocations.
//
// Decompressor is not safe for concurrent use.
type Decompressor struct {
	// SkipChecksum turns off validation of the Adler-32 trailer on zlib blobs.
	//
	// Verification is on by default and costs roughly 14% of decompression
	// time. Inflating catches most corruption on its own, and Decompress
	// independently requires the output to end exactly at Blob.raw_size, but
	// neither covers a stored (uncompressed) DEFLATE block: a flipped bit
	// there changes neither the stream's structure nor its length, so the
	// checksum is the only thing standing between it and the caller.
	//
	// Set it before the first call to Decompress, and only for input whose
	// integrity is already assured.
	SkipChecksum bool

	src   bytes.Reader
	inf   io.ReadCloser
	buf   []byte
	probe [1]byte // scratch for the end-of-stream check
}

// Decompress parses a raw Blob protobuf message and returns the decompressed
// payload. The returned slice points into the Decompressor's own storage and
// is valid until the next call to Decompress, whatever compression the Blob
// used.
func (d *Decompressor) Decompress(blob []byte) ([]byte, error) {
	var (
		rawData  []byte
		zlibData []byte
		rawSize  int
		hasRaw   bool
		hasZlib  bool
		m        msg
	)
	m.reset(blob)
	for m.next() {
		switch m.field {
		case 1: // raw
			rawData = m.bytes()
			hasRaw = true
		case 2: // raw_size
			n := m.int32()
			if m.err == nil && (n < 0 || n > maxBlobSize) {
				return nil, fmt.Errorf("osmbr: invalid Blob.raw_size: %d", n)
			}
			rawSize = int(n)
		case 3: // zlib_data
			zlibData = m.bytes()
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
			m.skip()
		}
	}
	if m.err != nil {
		return nil, fmt.Errorf("osmbr: Blob: %w", m.err)
	}

	switch {
	case hasRaw:
		return d.copyRaw(rawData), nil
	case hasZlib:
		return d.decompress(zlibData, rawSize)
	default:
		return nil, fmt.Errorf("osmbr: Blob contains no data")
	}
}

// copyRaw copies an uncompressed Blob payload into d.buf.
//
// Returning the subslice of blob would be free, but it would also tie the
// result's lifetime to the caller's blob buffer rather than to d: a
// BlockReader.Next that reuses its storage would then silently rewrite bytes
// the caller still holds, and a PrimitiveBlock's string table would end up
// pointing at the following block. Every Decompress result having one lifetime
// is worth a memcpy into an already-warm buffer.
func (d *Decompressor) copyRaw(raw []byte) []byte {
	if cap(d.buf) < len(raw) {
		d.buf = make([]byte, len(raw))
	}
	d.buf = d.buf[:len(raw)]
	copy(d.buf, raw)
	return d.buf
}

// decompress inflates a zlib stream into d.buf.
//
// It reads the zlib wrapper itself and drives compress/flate directly rather
// than going through compress/zlib, which would run every decompressed byte
// through Adler-32 whether or not the caller wants the check.
func (d *Decompressor) decompress(data []byte, rawSize int) ([]byte, error) {
	// Smallest possible stream: 2 header bytes, an empty final block, and the
	// 4-byte Adler-32 trailer.
	if len(data) < 8 {
		return nil, fmt.Errorf("osmbr: decompress: zlib stream too short: %d bytes", len(data))
	}
	cmf, flg := data[0], data[1]
	if cmf&0x0f != 8 {
		return nil, fmt.Errorf("osmbr: decompress: unsupported zlib compression method %d", cmf&0x0f)
	}
	if cmf>>4 > 7 {
		return nil, fmt.Errorf("osmbr: decompress: invalid zlib window size %d", cmf>>4)
	}
	if (uint(cmf)<<8|uint(flg))%31 != 0 {
		return nil, errors.New("osmbr: decompress: invalid zlib header")
	}
	if flg&0x20 != 0 {
		return nil, errors.New("osmbr: decompress: zlib preset dictionary not supported")
	}

	r, err := d.inflater(data[2:])
	if err != nil {
		return nil, fmt.Errorf("osmbr: decompress: %w", err)
	}

	if rawSize > 0 {
		if cap(d.buf) < rawSize {
			d.buf = make([]byte, rawSize)
		}
		d.buf = d.buf[:rawSize]
		if _, err = io.ReadFull(r, d.buf); err == nil {
			err = d.expectEOF(r)
		}
	} else {
		// raw_size absent: read until EOF into the persistent buffer, growing
		// as needed. Seeding from d.buf lets a warmed-up Decompressor hit this
		// path at zero allocs (vs. io.ReadAll, which always allocates).
		err = d.readAll(r)
	}
	if err != nil {
		d.discard()
		return nil, fmt.Errorf("osmbr: decompress: %w", err)
	}

	// bytes.Reader implements io.ByteReader, so flate stops it exactly after
	// the final DEFLATE block instead of buffering past the stream boundary.
	// A zlib stream must have precisely its four-byte Adler-32 trailer left at
	// that point; any other remainder means the trailer is missing, truncated,
	// or separated from DEFLATE by garbage.
	if remaining := d.src.Len(); remaining != 4 {
		return nil, fmt.Errorf("osmbr: decompress: %d bytes after DEFLATE, want 4-byte zlib trailer", remaining)
	}
	trailer := data[len(data)-d.src.Len():]
	if !d.SkipChecksum {
		want := binary.BigEndian.Uint32(trailer)
		if got := adler32.Checksum(d.buf); got != want {
			return nil, fmt.Errorf("osmbr: decompress: Adler-32 mismatch: got %08x, want %08x", got, want)
		}
	}

	return d.buf, nil
}

// expectEOF reports an error unless r is exhausted. Pairing it with a
// raw_size-sized ReadFull pins the output length exactly, which is what
// catches a truncated or overlong stream independently of the Adler-32
// trailer. Note it only applies when raw_size is present; without it, readAll
// has nothing to check the length against.
func (d *Decompressor) expectEOF(r io.Reader) error {
	n, err := r.Read(d.probe[:])
	if n > 0 {
		return errors.New("stream is longer than Blob.raw_size")
	}
	if err != nil && err != io.EOF {
		return err
	}
	return nil
}

// readAll fills d.buf with everything r produces, up to maxBlobSize. Without
// raw_size nothing else bounds the output, so this limit is what stops a
// decompression bomb.
func (d *Decompressor) readAll(r io.Reader) error {
	buf := d.buf[:0]
	if cap(buf) == 0 {
		buf = make([]byte, 0, 64*1024)
	}
	defer func() { d.buf = buf }()
	for {
		// len(buf) <= maxBlobSize here, so the read window is never empty.
		if len(buf) == cap(buf) {
			buf = append(buf, 0)[:len(buf)]
		}
		n, err := r.Read(buf[len(buf):min(cap(buf), maxBlobSize+1)])
		buf = buf[:len(buf)+n]
		if len(buf) > maxBlobSize {
			return fmt.Errorf("decompressed Blob exceeds %d bytes", maxBlobSize)
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// inflater returns a DEFLATE reader positioned at the start of body, reusing
// the previous one when possible.
func (d *Decompressor) inflater(body []byte) (io.Reader, error) {
	d.src.Reset(body)
	if d.inf != nil {
		// klauspost/compress/flate documents that NewReader's result also
		// implements Resetter. If that ever stops holding, fall back to
		// discarding the old reader and creating a fresh one.
		if rs, ok := d.inf.(flate.Resetter); ok {
			if err := rs.Reset(&d.src, nil); err != nil {
				d.discard()
				return nil, err
			}
			return d.inf, nil
		}
		d.inf.Close()
	}
	d.inf = flate.NewReader(&d.src)
	return d.inf, nil
}

// discard drops the inflater so the next call starts from a clean one.
func (d *Decompressor) discard() {
	if d.inf != nil {
		d.inf.Close()
		d.inf = nil
	}
}
