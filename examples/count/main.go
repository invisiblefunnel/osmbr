// Example count reads a PBF file and counts blocks and entity versions.
// It demonstrates parallel decompression and decoding using BlockReader,
// Decompressor, and worker goroutines with pooled buffers.
//
// Usage:
//
//	go run ./examples/count region.osm.pbf
//	go run ./examples/count -workers 4 region.osm.pbf
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/invisiblefunnel/osmbr"
)

type result struct {
	nodes, ways, relations int64
}

func main() {
	numWorkers := flag.Int("workers", runtime.GOMAXPROCS(0), "number of parallel decode workers")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "usage: count [flags] <file.osm.pbf>\n")
		os.Exit(1)
	}

	f, err := os.Open(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()

	var bufPool sync.Pool
	jobs := make(chan []byte, *numWorkers)
	results := make(chan result, *numWorkers)
	var blocks atomic.Int64

	// Workers: each has its own decompressor and decode buffers.
	var wg sync.WaitGroup
	for range *numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var (
				dec   osmbr.Decompressor
				pb    osmbr.PrimitiveBlock
				dnBuf osmbr.DenseNodesBuf
				nBuf  osmbr.NodeBuf
				wBuf  osmbr.WayBuf
				rBuf  osmbr.RelationBuf
			)
			for blob := range jobs {
				var r result
				data, err := dec.Decompress(blob)
				bufPool.Put(blob[:0])
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					results <- r
					continue
				}
				if err := pb.DecodeFrom(data); err != nil {
					fmt.Fprintln(os.Stderr, err)
					results <- r
					continue
				}
				gs := pb.Groups()
				for gs.Next() {
					switch gs.Type() {
					case osmbr.GroupTypeDense:
						if err := gs.DecodeDenseNodes(&dnBuf, nil); err != nil {
							fmt.Fprintln(os.Stderr, err)
							continue
						}
						r.nodes += int64(len(dnBuf.IDs))
					case osmbr.GroupTypeNodes:
						ns := gs.NodeScanner()
						for _, _, _, ok := ns.Next(&nBuf, nil); ok; _, _, _, ok = ns.Next(&nBuf, nil) {
							r.nodes++
						}
					case osmbr.GroupTypeWays:
						ws := gs.WayScanner()
						for _, ok := ws.Next(&wBuf, nil); ok; _, ok = ws.Next(&wBuf, nil) {
							r.ways++
						}
					case osmbr.GroupTypeRelations:
						rs := gs.RelationScanner()
						for _, ok := rs.Next(&rBuf, nil); ok; _, ok = rs.Next(&rBuf, nil) {
							r.relations++
						}
					}
				}
				results <- r
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// Producer: read raw blob bytes (I/O only, no decompression),
	// copy into pooled buffers, send to workers.
	var readErr error
	go func() {
		br := osmbr.NewBlockReader(f)
		for br.Next() {
			if br.Type() != "OSMData" {
				continue
			}
			src := br.Blob()
			blocks.Add(1)

			buf, _ := bufPool.Get().([]byte)
			buf = append(buf, src...)

			jobs <- buf
		}
		readErr = br.Err()
		close(jobs)
	}()

	// Aggregate results.
	start := time.Now()
	var done, nodes, ways, relations int64
	for r := range results {
		done++
		nodes += r.nodes
		ways += r.ways
		relations += r.relations
		if done%1000 == 0 {
			fmt.Fprintf(os.Stderr, "[%s] %d blocks, %d nodes, %d ways, %d relations\n",
				time.Since(start).Round(time.Second), done, nodes, ways, relations)
		}
	}
	if readErr != nil {
		fmt.Fprintln(os.Stderr, readErr)
		os.Exit(1)
	}

	fmt.Printf("File:      %s\n", flag.Arg(0))
	fmt.Printf("Elapsed:   %s\n", time.Since(start).Round(time.Second))
	fmt.Printf("Blocks:    %d\n", blocks.Load())
	fmt.Printf("Nodes:     %d\n", nodes)
	fmt.Printf("Ways:      %d\n", ways)
	fmt.Printf("Relations: %d\n", relations)
}
