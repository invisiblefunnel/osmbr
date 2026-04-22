package osmbr_test

import (
	"fmt"
	"os"

	"github.com/invisiblefunnel/osmbr"
)

// The examples below read a small slice of the bundled testdata file.
// In real code, path would be any OSM PBF file.

func ExampleBlockReader() {
	f, err := os.Open("testdata/us-virgin-islands-260414.osm.pbf")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()

	br := osmbr.NewBlockReader(f)
	for br.Next() {
		fmt.Printf("type=%s offset=%d len=%d\n", br.Type(), br.Offset(), len(br.Blob()))
		break // first block only for the example
	}
	if err := br.Err(); err != nil {
		fmt.Println(err)
	}
	// Output: type=OSMHeader offset=0 len=193
}

func ExampleDecompressor() {
	f, err := os.Open("testdata/us-virgin-islands-260414.osm.pbf")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()

	var dec osmbr.Decompressor
	br := osmbr.NewBlockReader(f)
	if !br.Next() {
		fmt.Println("no blocks")
		return
	}
	data, err := dec.Decompress(br.Blob())
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("decompressed %d bytes\n", len(data))
	// Output: decompressed 179 bytes
}

func ExamplePrimitiveBlock_Groups() {
	f, err := os.Open("testdata/us-virgin-islands-260414.osm.pbf")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()

	var (
		dec osmbr.Decompressor
		pb  osmbr.PrimitiveBlock
	)
	br := osmbr.NewBlockReader(f)
	for br.Next() {
		if br.Type() != "OSMData" {
			continue
		}
		data, err := dec.Decompress(br.Blob())
		if err != nil {
			fmt.Println(err)
			return
		}
		if err := pb.DecodeFrom(data); err != nil {
			fmt.Println(err)
			return
		}
		gs := pb.Groups()
		for gs.Next() {
			fmt.Printf("group type=%d\n", gs.Type())
		}
		break // one OSMData block is enough for the example
	}
	// Output: group type=2
}

func ExampleDenseNodesBuf() {
	f, err := os.Open("testdata/us-virgin-islands-260414.osm.pbf")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()

	var (
		dec   osmbr.Decompressor
		pb    osmbr.PrimitiveBlock
		dnBuf osmbr.DenseNodesBuf
	)
	br := osmbr.NewBlockReader(f)
	for br.Next() {
		if br.Type() != "OSMData" {
			continue
		}
		data, err := dec.Decompress(br.Blob())
		if err != nil {
			fmt.Println(err)
			return
		}
		if err := pb.DecodeFrom(data); err != nil {
			fmt.Println(err)
			return
		}
		gs := pb.Groups()
		for gs.Next() {
			if gs.Type() != osmbr.GroupTypeDense {
				continue
			}
			if err := gs.DecodeDenseNodes(&dnBuf, nil); err != nil {
				fmt.Println(err)
				return
			}
			// Convert the first node's raw lat/lon to nanodegrees.
			latNanodeg := dnBuf.Lats[0]*int64(pb.Granularity) + pb.LatOffset
			lonNanodeg := dnBuf.Lons[0]*int64(pb.Granularity) + pb.LonOffset
			fmt.Printf("first node id=%d lat=%d lon=%d\n",
				dnBuf.IDs[0], latNanodeg, lonNanodeg)
			return
		}
	}
	// Output: first node id=38344686 lat=17757614800 lon=-64585070900
}
