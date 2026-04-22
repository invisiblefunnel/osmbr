package osmbr_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/invisiblefunnel/osmbr"
)

// loadFirstDataBlock reads the first OSMData block from the bundled test PBF
// and returns its decompressed bytes. Used to seed fuzz corpora with
// realistic input that exercises the happy path.
func loadFirstDataBlock(tb testing.TB) (raw []byte, dataBlock []byte, headerBlob []byte) {
	tb.Helper()
	f, err := os.Open(testFile)
	if err != nil {
		tb.Skipf("testdata unavailable: %v", err)
	}
	defer f.Close()

	br := osmbr.NewBlockReader(f)
	var dec osmbr.Decompressor
	for br.Next() {
		switch br.Type() {
		case "OSMHeader":
			if headerBlob == nil {
				headerBlob = append([]byte(nil), br.Blob()...)
			}
		case "OSMData":
			raw = append([]byte(nil), br.Blob()...)
			out, err := dec.Decompress(raw)
			if err != nil {
				tb.Fatalf("seed Decompress: %v", err)
			}
			dataBlock = append([]byte(nil), out...)
			return raw, dataBlock, headerBlob
		}
	}
	tb.Skip("no OSMData block in testdata")
	return nil, nil, nil
}

func FuzzBlockReader(f *testing.F) {
	// Seeds: empty, tiny garbage, a synthetic well-formed frame.
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add(pbfFrame("OSMData", pbLenDelim(1, []byte("payload"))))

	f.Fuzz(func(t *testing.T, data []byte) {
		br := osmbr.NewBlockReader(bytes.NewReader(data))
		for i := 0; br.Next(); i++ {
			_ = br.Type()
			_ = br.Blob()
			_ = br.Offset()
			if i > 1024 {
				t.Fatalf("BlockReader produced > 1024 blocks on %d input bytes", len(data))
			}
		}
		_ = br.Err()
	})
}

func FuzzDecompressor(f *testing.F) {
	// Seeds: empty, raw blob, invalid compression marker.
	f.Add([]byte{})
	f.Add(pbLenDelim(1, []byte("raw payload")))
	f.Add(pbLenDelim(4, []byte("lzma"))) // unsupported compression

	f.Fuzz(func(t *testing.T, blob []byte) {
		var dec osmbr.Decompressor
		_, _ = dec.Decompress(blob)
		// Second call with same blob — decompressor must survive reuse.
		_, _ = dec.Decompress(blob)
	})
}

func FuzzDecodeHeader(f *testing.F) {
	f.Add([]byte{})
	f.Add(pbLenDelim(4, []byte("OsmSchema-V0.6")))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = osmbr.DecodeHeader(data)
	})
}

func FuzzPrimitiveBlockDecodeFrom(f *testing.F) {
	// Seeds: empty, a bare stringtable, and a realistic block if testdata exists.
	f.Add([]byte{})
	f.Add(pbLenDelim(1, pbLenDelim(1, []byte("highway"))))

	if _, dataBlock, _ := loadFirstDataBlock(f); dataBlock != nil {
		f.Add(dataBlock)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var pb osmbr.PrimitiveBlock
		if err := pb.DecodeFrom(data); err != nil {
			return
		}
		_ = pb.NumStrings()
		gs := pb.Groups()
		for i := 0; gs.Next(); i++ {
			_ = gs.Type()
			if i > 4096 {
				t.Fatalf("groups did not terminate on %d input bytes", len(data))
			}
		}
		_ = gs.Err()
	})
}

func FuzzDecodeDenseNodes(f *testing.F) {
	f.Add([]byte{})
	f.Add(pbLenDelim(2, pbPackedSint64(1, []int64{1, 1, 1})))

	f.Fuzz(func(t *testing.T, data []byte) {
		var buf osmbr.DenseNodesBuf
		_ = osmbr.DecodeDenseNodes(data, &buf, nil)

		var info osmbr.DenseInfoBuf
		_ = osmbr.DecodeDenseNodes(data, &buf, &info)
	})
}
