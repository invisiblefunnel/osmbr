package osmbr_test

import (
	"io"
	"maps"
	"math"
	"os"
	"slices"
	"testing"

	"github.com/invisiblefunnel/osmbr"
)

const testFile = "testdata/us-virgin-islands-260414.osm.pbf"

func TestReadAll(t *testing.T) {
	f, err := os.Open(testFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var (
		pb    osmbr.PrimitiveBlock
		dnBuf osmbr.DenseNodesBuf
		diBuf osmbr.DenseInfoBuf
		nBuf  osmbr.NodeBuf
		wBuf  osmbr.WayBuf
		rBuf  osmbr.RelationBuf
		iBuf  osmbr.InfoBuf

		blocks, nodes, ways, relations int64
		hasHeader                      bool
	)

	var dec osmbr.Decompressor
	br := osmbr.NewBlockReader(f)
	for br.Next() {
		if br.Type() == "OSMHeader" {
			hasHeader = true
			continue
		}
		if br.Type() != "OSMData" {
			continue
		}
		blocks++

		data, err := dec.Decompress(br.Blob())
		if err != nil {
			t.Fatalf("block %d: Decompress: %v", blocks, err)
		}
		if err := pb.DecodeFrom(data); err != nil {
			t.Fatalf("block %d: DecodeFrom: %v", blocks, err)
		}

		gs := pb.Groups()
		for gs.Next() {
			switch gs.Type() {
			case osmbr.GroupTypeDense:
				if err := gs.DecodeDenseNodes(&dnBuf, &diBuf); err != nil {
					t.Fatalf("block %d: DecodeDenseNodes: %v", blocks, err)
				}
				if len(dnBuf.IDs) != len(dnBuf.Lats) || len(dnBuf.IDs) != len(dnBuf.Lons) {
					t.Fatalf("block %d: dense length mismatch: IDs=%d Lats=%d Lons=%d",
						blocks, len(dnBuf.IDs), len(dnBuf.Lats), len(dnBuf.Lons))
				}
				if len(diBuf.Versions) != len(dnBuf.IDs) {
					t.Fatalf("block %d: dense info length mismatch: Versions=%d IDs=%d",
						blocks, len(diBuf.Versions), len(dnBuf.IDs))
				}
				nodes += int64(len(dnBuf.IDs))

			case osmbr.GroupTypeNodes:
				ns := gs.NodeScanner()
				for _, _, _, ok := ns.Next(&nBuf, &iBuf); ok; _, _, _, ok = ns.Next(&nBuf, &iBuf) {
					nodes++
				}
				if err := ns.Err(); err != nil {
					t.Fatalf("block %d: NodeScanner: %v", blocks, err)
				}

			case osmbr.GroupTypeWays:
				ws := gs.WayScanner()
				for _, ok := ws.Next(&wBuf, &iBuf); ok; _, ok = ws.Next(&wBuf, &iBuf) {
					if len(wBuf.Keys) != len(wBuf.Vals) {
						t.Fatalf("block %d: way keys/vals mismatch: %d != %d",
							blocks, len(wBuf.Keys), len(wBuf.Vals))
					}
					ways++
				}
				if err := ws.Err(); err != nil {
					t.Fatalf("block %d: WayScanner: %v", blocks, err)
				}

			case osmbr.GroupTypeRelations:
				rs := gs.RelationScanner()
				for _, ok := rs.Next(&rBuf, &iBuf); ok; _, ok = rs.Next(&rBuf, &iBuf) {
					if len(rBuf.Keys) != len(rBuf.Vals) {
						t.Fatalf("block %d: relation keys/vals mismatch: %d != %d",
							blocks, len(rBuf.Keys), len(rBuf.Vals))
					}
					if len(rBuf.MemIDs) != len(rBuf.Types) {
						t.Fatalf("block %d: relation memids/types mismatch: %d != %d",
							blocks, len(rBuf.MemIDs), len(rBuf.Types))
					}
					relations++
				}
				if err := rs.Err(); err != nil {
					t.Fatalf("block %d: RelationScanner: %v", blocks, err)
				}
			}
		}
	}
	if err := br.Err(); err != nil {
		t.Fatal(err)
	}

	if !hasHeader {
		t.Error("missing OSMHeader block")
	}
	if blocks != 67 {
		t.Errorf("blocks = %d, want 67", blocks)
	}
	if nodes != 453760 {
		t.Errorf("nodes = %d, want 453760", nodes)
	}
	if ways != 65146 {
		t.Errorf("ways = %d, want 65146", ways)
	}
	if relations != 312 {
		t.Errorf("relations = %d, want 312", relations)
	}
}

func TestBlockOffsets(t *testing.T) {
	f, err := os.Open(testFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// First pass: record each block's offset and type.
	type blockInfo struct {
		offset int64
		typ    string
	}
	var blocks []blockInfo

	br := osmbr.NewBlockReader(f)
	for br.Next() {
		blocks = append(blocks, blockInfo{offset: br.Offset(), typ: br.Type()})
	}
	if err := br.Err(); err != nil {
		t.Fatal(err)
	}
	if len(blocks) == 0 {
		t.Fatal("no blocks found")
	}
	if blocks[0].offset != 0 {
		t.Errorf("first block offset = %d, want 0", blocks[0].offset)
	}

	// Second pass: seek to each recorded offset and verify we read the same block type.
	for i, b := range blocks {
		if _, err := f.Seek(b.offset, io.SeekStart); err != nil {
			t.Fatalf("block %d: seek to %d: %v", i, b.offset, err)
		}
		br2 := osmbr.NewBlockReader(f)
		if !br2.Next() {
			t.Fatalf("block %d: Next returned false at offset %d", i, b.offset)
		}
		if br2.Type() != b.typ {
			t.Errorf("block %d at offset %d: type = %q, want %q", i, b.offset, br2.Type(), b.typ)
		}
	}
}

func TestHeader(t *testing.T) {
	f, err := os.Open(testFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var dec osmbr.Decompressor
	br := osmbr.NewBlockReader(f)
	if !br.Next() {
		t.Fatal("expected a block")
	}
	if br.Type() != "OSMHeader" {
		t.Fatalf("first block type = %q, want OSMHeader", br.Type())
	}

	data, err := dec.Decompress(br.Blob())
	if err != nil {
		t.Fatal(err)
	}
	h, err := osmbr.DecodeHeader(data)
	if err != nil {
		t.Fatal(err)
	}

	// BBox (nanodegrees → degrees for comparison)
	checkCoord := func(name string, got int64, wantDeg float64) {
		gotDeg := float64(got) / 1e9
		if math.Abs(gotDeg-wantDeg) > 1e-7 {
			t.Errorf("BBox.%s = %.7f, want %.7f", name, gotDeg, wantDeg)
		}
	}
	checkCoord("Bottom", h.BBox.Bottom, 17.2824650)
	checkCoord("Top", h.BBox.Top, 18.4859590)
	checkCoord("Left", h.BBox.Left, -65.1750200)
	checkCoord("Right", h.BBox.Right, -63.9555370)

	wantRequired := []string{"OsmSchema-V0.6", "DenseNodes"}
	if !slices.Equal(h.RequiredFeatures, wantRequired) {
		t.Errorf("RequiredFeatures = %v, want %v", h.RequiredFeatures, wantRequired)
	}

	wantOptional := []string{"Sort.Type_then_ID"}
	if !slices.Equal(h.OptionalFeatures, wantOptional) {
		t.Errorf("OptionalFeatures = %v, want %v", h.OptionalFeatures, wantOptional)
	}

	if h.WritingProgram != "osmium/1.16.0" {
		t.Errorf("WritingProgram = %q, want %q", h.WritingProgram, "osmium/1.16.0")
	}

	if h.ReplicationTimestamp != 1776198090 {
		t.Errorf("ReplicationTimestamp = %d, want 1776198090", h.ReplicationTimestamp)
	}

	if h.ReplicationSequenceNumber != 1602 {
		t.Errorf("ReplicationSequenceNumber = %d, want 1602", h.ReplicationSequenceNumber)
	}

	wantURL := "https://download.geofabrik.de/north-america/us/us-virgin-islands-updates"
	if h.ReplicationBaseURL != wantURL {
		t.Errorf("ReplicationBaseURL = %q, want %q", h.ReplicationBaseURL, wantURL)
	}
}

// Expected values below are derived from github.com/paulmach/osm v0.9.0 reading
// the same PBF file. That library is NOT a dependency of this package; the values
// are hardcoded so the tests are self-contained.

func TestNodeValues(t *testing.T) {
	type nodeExpect struct {
		lat, lon    float64
		tags        map[string]string
		version     int32
		timestampMs int64
	}

	want := map[int64]nodeExpect{
		// Untagged node
		38344686: {
			lat: 17.7576148, lon: -64.5850709,
			version: 31, timestampMs: 1728691475000,
		},
		// Untagged node
		248716806: {
			lat: 18.3488721, lon: -64.8642093,
			version: 2, timestampMs: 1485607158000,
		},
		// Tagged node (2 tags)
		249532862: {
			lat: 18.3351665, lon: -64.8503132,
			tags:    map[string]string{"ele": "5", "gnis:feature_id": "1993610"},
			version: 10, timestampMs: 1723586759000,
		},
		// Tagged node (2 tags)
		249992888: {
			lat: 18.3400534, lon: -64.8875363,
			tags:    map[string]string{"highway": "traffic_signals", "traffic_signals": "signal"},
			version: 4, timestampMs: 1653238369000,
		},
	}

	got := make(map[int64]nodeExpect)

	f, err := os.Open(testFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var (
		dec   osmbr.Decompressor
		pb    osmbr.PrimitiveBlock
		dnBuf osmbr.DenseNodesBuf
		diBuf osmbr.DenseInfoBuf
	)

	br := osmbr.NewBlockReader(f)
	for br.Next() {
		if br.Type() != "OSMData" {
			continue
		}
		data, err := dec.Decompress(br.Blob())
		if err != nil {
			t.Fatal(err)
		}
		if err := pb.DecodeFrom(data); err != nil {
			t.Fatal(err)
		}

		gs := pb.Groups()
		for gs.Next() {
			if gs.Type() != osmbr.GroupTypeDense {
				continue
			}
			if err := gs.DecodeDenseNodes(&dnBuf, &diBuf); err != nil {
				t.Fatal(err)
			}

			j := 0
			for i, id := range dnBuf.IDs {
				// Collect this node's tags
				var tags map[string]string
				if len(dnBuf.KeysVals) > 0 {
					m := map[string]string{}
					for j < len(dnBuf.KeysVals) && dnBuf.KeysVals[j] != 0 {
						key := string(pb.String(int(dnBuf.KeysVals[j])))
						val := string(pb.String(int(dnBuf.KeysVals[j+1])))
						m[key] = val
						j += 2
					}
					if j < len(dnBuf.KeysVals) {
						j++ // skip 0 delimiter
					}
					if len(m) > 0 {
						tags = m
					}
				}

				if _, needed := want[id]; needed {
					lat := float64(dnBuf.Lats[i]*int64(pb.Granularity)+pb.LatOffset) / 1e9
					lon := float64(dnBuf.Lons[i]*int64(pb.Granularity)+pb.LonOffset) / 1e9
					got[id] = nodeExpect{
						lat:         lat,
						lon:         lon,
						tags:        tags,
						version:     diBuf.Versions[i],
						timestampMs: diBuf.Timestamps[i] * int64(pb.DateGranularity),
					}
				}
			}
		}
		if len(got) == len(want) {
			break
		}
	}
	if err := br.Err(); err != nil {
		t.Fatal(err)
	}

	for id, w := range want {
		g, ok := got[id]
		if !ok {
			t.Errorf("node %d: not found", id)
			continue
		}
		if math.Abs(g.lat-w.lat) > 1e-7 {
			t.Errorf("node %d: lat = %v, want %v", id, g.lat, w.lat)
		}
		if math.Abs(g.lon-w.lon) > 1e-7 {
			t.Errorf("node %d: lon = %v, want %v", id, g.lon, w.lon)
		}
		if !maps.Equal(g.tags, w.tags) {
			t.Errorf("node %d: tags = %v, want %v", id, g.tags, w.tags)
		}
		if g.version != w.version {
			t.Errorf("node %d: version = %d, want %d", id, g.version, w.version)
		}
		if g.timestampMs != w.timestampMs {
			t.Errorf("node %d: timestamp = %d, want %d", id, g.timestampMs, w.timestampMs)
		}
	}
}

func TestWayValues(t *testing.T) {
	type wayExpect struct {
		refs        []int64
		tags        map[string]string
		version     int32
		timestampMs int64
	}

	want := map[int64]wayExpect{
		// Small way (3 refs, 1 tag)
		23049065: {
			refs:        []int64{248716808, 248716807, 248716806},
			tags:        map[string]string{"man_made": "pier"},
			version:     3,
			timestampMs: 1485607159000,
		},
		// Small way (2 refs, 3 tags)
		23130799: {
			refs: []int64{249753687, 249753688},
			tags: map[string]string{"access": "private", "highway": "footway", "man_made": "pier"},
			version:     3,
			timestampMs: 1560846714000,
		},
		// Larger way (12 refs, 4 tags)
		5358865: {
			refs: []int64{
				310748060, 310748061, 310748062, 314662007, 314661910, 313009587,
				310748572, 313009576, 313009355, 7147483276, 310748125, 310748063,
			},
			tags: map[string]string{
				"highway":  "trunk",
				"maxspeed": "20",
				"name":     "Queen Mary Highway / Centerline Road",
				"ref":      "VI 70",
			},
			version:     51,
			timestampMs: 1689028355000,
		},
	}

	got := make(map[int64]wayExpect)

	f, err := os.Open(testFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var (
		dec  osmbr.Decompressor
		pb   osmbr.PrimitiveBlock
		wBuf osmbr.WayBuf
		iBuf osmbr.InfoBuf
	)

	br := osmbr.NewBlockReader(f)
	for br.Next() {
		if br.Type() != "OSMData" {
			continue
		}
		data, err := dec.Decompress(br.Blob())
		if err != nil {
			t.Fatal(err)
		}
		if err := pb.DecodeFrom(data); err != nil {
			t.Fatal(err)
		}

		gs := pb.Groups()
		for gs.Next() {
			if gs.Type() != osmbr.GroupTypeWays {
				continue
			}
			ws := gs.WayScanner()
			for id, ok := ws.Next(&wBuf, &iBuf); ok; id, ok = ws.Next(&wBuf, &iBuf) {
				if _, needed := want[id]; !needed {
					continue
				}
				tags := make(map[string]string, len(wBuf.Keys))
				for i := range wBuf.Keys {
					tags[string(pb.String(int(wBuf.Keys[i])))] = string(pb.String(int(wBuf.Vals[i])))
				}
				refs := make([]int64, len(wBuf.Refs))
				copy(refs, wBuf.Refs)
				got[id] = wayExpect{
					refs:        refs,
					tags:        tags,
					version:     iBuf.Version,
					timestampMs: iBuf.Timestamp * int64(pb.DateGranularity),
				}
			}
			if err := ws.Err(); err != nil {
				t.Fatal(err)
			}
		}
		if len(got) == len(want) {
			break
		}
	}
	if err := br.Err(); err != nil {
		t.Fatal(err)
	}

	for id, w := range want {
		g, ok := got[id]
		if !ok {
			t.Errorf("way %d: not found", id)
			continue
		}
		if !slices.Equal(g.refs, w.refs) {
			t.Errorf("way %d: refs = %v, want %v", id, g.refs, w.refs)
		}
		if !maps.Equal(g.tags, w.tags) {
			t.Errorf("way %d: tags = %v, want %v", id, g.tags, w.tags)
		}
		if g.version != w.version {
			t.Errorf("way %d: version = %d, want %d", id, g.version, w.version)
		}
		if g.timestampMs != w.timestampMs {
			t.Errorf("way %d: timestamp = %d, want %d", id, g.timestampMs, w.timestampMs)
		}
	}
}

func TestRelationValues(t *testing.T) {
	type memberExpect struct {
		id   int64
		typ  int32
		role string
	}

	type relExpect struct {
		members     []memberExpect
		tags        map[string]string
		version     int32
		timestampMs int64
	}

	want := map[int64]relExpect{
		// Simple multipolygon (3 way members, 2 tags)
		50856: {
			members: []memberExpect{
				{28350789, osmbr.MemberTypeWay, "outer"},
				{28350800, osmbr.MemberTypeWay, "inner"},
				{28350805, osmbr.MemberTypeWay, "inner"},
			},
			tags:        map[string]string{"building": "yes", "type": "multipolygon"},
			version:     6,
			timestampMs: 1490305910000,
		},
		// Mixed member types: 13 ways + 1 node
		254585: {
			members: []memberExpect{
				{220100304, osmbr.MemberTypeWay, "outer"},
				{220098097, osmbr.MemberTypeWay, "outer"},
				{220098091, osmbr.MemberTypeWay, "outer"},
				{1301451583, osmbr.MemberTypeWay, "outer"},
				{220098089, osmbr.MemberTypeWay, "outer"},
				{220098106, osmbr.MemberTypeWay, "outer"},
				{220100300, osmbr.MemberTypeWay, "outer"},
				{41051635, osmbr.MemberTypeWay, "outer"},
				{220100301, osmbr.MemberTypeWay, "outer"},
				{220098103, osmbr.MemberTypeWay, "outer"},
				{1301444066, osmbr.MemberTypeWay, "outer"},
				{220098101, osmbr.MemberTypeWay, "outer"},
				{41051641, osmbr.MemberTypeWay, "outer"},
				{356559196, osmbr.MemberTypeNode, "highest_point"},
			},
			tags: map[string]string{
				"border_type":        "district",
				"boundary":           "census",
				"ele":                "270",
				"gnis:feature_id":    "1614296",
				"is_in:country":      "U.S. Virgin Islands",
				"is_in:country_code": "VI",
				"name":               "Saint John",
				"name:cs":            "Svatý Jan",
				"name:da":            "Sankt Jan",
				"place":              "island",
				"short_name":         "St. John",
				"type":               "boundary",
				"wikidata":           "Q849441",
				"wikipedia":          "en:Saint John, U.S. Virgin Islands",
			},
			version:     12,
			timestampMs: 1755374814000,
		},
	}

	got := make(map[int64]relExpect)

	f, err := os.Open(testFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var (
		dec  osmbr.Decompressor
		pb   osmbr.PrimitiveBlock
		rBuf osmbr.RelationBuf
		iBuf osmbr.InfoBuf
	)

	br := osmbr.NewBlockReader(f)
	for br.Next() {
		if br.Type() != "OSMData" {
			continue
		}
		data, err := dec.Decompress(br.Blob())
		if err != nil {
			t.Fatal(err)
		}
		if err := pb.DecodeFrom(data); err != nil {
			t.Fatal(err)
		}

		gs := pb.Groups()
		for gs.Next() {
			if gs.Type() != osmbr.GroupTypeRelations {
				continue
			}
			rs := gs.RelationScanner()
			for id, ok := rs.Next(&rBuf, &iBuf); ok; id, ok = rs.Next(&rBuf, &iBuf) {
				if _, needed := want[id]; !needed {
					continue
				}
				tags := make(map[string]string, len(rBuf.Keys))
				for i := range rBuf.Keys {
					tags[string(pb.String(int(rBuf.Keys[i])))] = string(pb.String(int(rBuf.Vals[i])))
				}
				members := make([]memberExpect, len(rBuf.MemIDs))
				for i := range rBuf.MemIDs {
					members[i] = memberExpect{
						id:   rBuf.MemIDs[i],
						typ:  rBuf.Types[i],
						role: string(pb.String(int(rBuf.RolesSID[i]))),
					}
				}
				got[id] = relExpect{
					members:     members,
					tags:        tags,
					version:     iBuf.Version,
					timestampMs: iBuf.Timestamp * int64(pb.DateGranularity),
				}
			}
			if err := rs.Err(); err != nil {
				t.Fatal(err)
			}
		}
		if len(got) == len(want) {
			break
		}
	}
	if err := br.Err(); err != nil {
		t.Fatal(err)
	}

	for id, w := range want {
		g, ok := got[id]
		if !ok {
			t.Errorf("relation %d: not found", id)
			continue
		}
		if len(g.members) != len(w.members) {
			t.Errorf("relation %d: %d members, want %d", id, len(g.members), len(w.members))
		} else {
			for i, wm := range w.members {
				gm := g.members[i]
				if gm.id != wm.id || gm.typ != wm.typ || gm.role != wm.role {
					t.Errorf("relation %d member %d: got {id:%d type:%d role:%q}, want {id:%d type:%d role:%q}",
						id, i, gm.id, gm.typ, gm.role, wm.id, wm.typ, wm.role)
				}
			}
		}
		if !maps.Equal(g.tags, w.tags) {
			t.Errorf("relation %d: tags = %v, want %v", id, g.tags, w.tags)
		}
		if g.version != w.version {
			t.Errorf("relation %d: version = %d, want %d", id, g.version, w.version)
		}
		if g.timestampMs != w.timestampMs {
			t.Errorf("relation %d: timestamp = %d, want %d", id, g.timestampMs, w.timestampMs)
		}
	}
}
