package osmbr_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/invisiblefunnel/osmbr"
)

func BenchmarkReadAll(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		f, err := os.Open("us-west-latest.osm.pbf")
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()

		var (
			pb    osmbr.PrimitiveBlock
			dnBuf osmbr.DenseNodesBuf
			wBuf  osmbr.WayBuf
			rBuf  osmbr.RelationBuf
			nBuf  osmbr.NodeBuf

			nodes, ways, relations int64
		)

		br := osmbr.NewBlockReader(f)
		for br.Next() {
			if br.Type() != "OSMData" {
				continue
			}
			if err := pb.DecodeFrom(br.Data()); err != nil {
				b.Fatal(err)
			}

			gs := pb.Groups()
			for gs.Next() {
				switch gs.Type() {
				case osmbr.GroupTypeDense:
					if err := gs.DecodeDenseNodes(&dnBuf, nil); err != nil {
						b.Fatal(err)
					}
					nodes += int64(len(dnBuf.IDs))

				case osmbr.GroupTypeNodes:
					ns := gs.NodeScanner()
					for _, _, _, ok := ns.Next(&nBuf, nil); ok; _, _, _, ok = ns.Next(&nBuf, nil) {
						nodes++
					}
					if err := ns.Err(); err != nil {
						b.Fatal(err)
					}

				case osmbr.GroupTypeWays:
					ws := gs.WayScanner()
					for _, ok := ws.Next(&wBuf, nil); ok; _, ok = ws.Next(&wBuf, nil) {
						ways++
					}
					if err := ws.Err(); err != nil {
						b.Fatal(err)
					}

				case osmbr.GroupTypeRelations:
					rs := gs.RelationScanner()
					for _, ok := rs.Next(&rBuf, nil); ok; _, ok = rs.Next(&rBuf, nil) {
						relations++
					}
					if err := rs.Err(); err != nil {
						b.Fatal(err)
					}
				}
			}
		}
		if err := br.Err(); err != nil {
			b.Fatal(err)
		}

		b.StopTimer()
		f.Close()
		b.ReportMetric(float64(nodes), "nodes")
		b.ReportMetric(float64(ways), "ways")
		b.ReportMetric(float64(relations), "relations")
		_ = fmt.Sprintf // suppress unused import if compiler optimizes away the metric call
		b.StartTimer()
	}
}
