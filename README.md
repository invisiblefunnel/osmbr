# osmbr

A low-level Go library for reading OpenStreetMap [PBF files](https://wiki.openstreetmap.org/wiki/PBF_Format). Designed for minimal allocation and caller-controlled memory.

## Design

- **Caller-managed buffers** — Allocate buffer structs once and reuse them across blocks. After warm-up, the hot path makes zero heap allocations.
- **Scanner pattern** — Standard `for scanner.Next() { ... }` idiom with sticky errors.
- **Raw values** — Returns raw integers for coordinates and string-table indices for tags. The caller applies granularity/offset conversion.
- **No domain types** — There are no `Node`, `Way`, or `Relation` structs. The caller reads fields from buffer structs and builds whatever representation it needs.

## Install

```
go get github.com/invisiblefunnel/osmbr
```

Requires Go 1.24 or later.

## Usage

```go
f, err := os.Open("region.osm.pbf")
if err != nil {
    log.Fatal(err)
}
defer f.Close()

var (
    pb    osmbr.PrimitiveBlock
    dnBuf osmbr.DenseNodesBuf
    wBuf  osmbr.WayBuf
    rBuf  osmbr.RelationBuf
)

br := osmbr.NewBlockReader(f)
for br.Next() {
    if br.Type() != "OSMData" {
        continue
    }
    if err := pb.DecodeFrom(br.Data()); err != nil {
        log.Fatal(err)
    }

    gs := pb.Groups()
    for gs.Next() {
        switch gs.Type() {
        case osmbr.GroupTypeDense:
            if err := gs.DecodeDenseNodes(&dnBuf, nil); err != nil {
                log.Fatal(err)
            }
            for i, id := range dnBuf.IDs {
                lat := dnBuf.Lats[i]*int64(pb.Granularity) + pb.LatOffset
                lon := dnBuf.Lons[i]*int64(pb.Granularity) + pb.LonOffset
                _ = id
                _ = lat
                _ = lon
            }

        case osmbr.GroupTypeWays:
            ws := gs.WayScanner()
            for id, ok := ws.Next(&wBuf, nil); ok; id, ok = ws.Next(&wBuf, nil) {
                _ = id       // way ID
                _ = wBuf.Refs // referenced node IDs (absolute)
            }
            if err := ws.Err(); err != nil {
                log.Fatal(err)
            }

        case osmbr.GroupTypeRelations:
            rs := gs.RelationScanner()
            for id, ok := rs.Next(&rBuf, nil); ok; id, ok = rs.Next(&rBuf, nil) {
                _ = id          // relation ID
                _ = rBuf.MemIDs // member IDs (absolute)
                _ = rBuf.Types  // member types (MemberTypeNode, MemberTypeWay, MemberTypeRelation)
            }
            if err := rs.Err(); err != nil {
                log.Fatal(err)
            }
        }
    }
}
if err := br.Err(); err != nil {
    log.Fatal(err)
}
```

## API overview

The reading pipeline flows top-down:

### BlockReader

`NewBlockReader(r io.Reader)` reads and decompresses PBF file blocks sequentially. Call `Next()` to advance, `Type()` for the block type (`"OSMHeader"` or `"OSMData"`), and `Data()` for the decompressed protobuf bytes. Uses [klauspost/compress](https://github.com/klauspost/compress) for zlib decompression with reusable decompressor state.

### PrimitiveBlock

`DecodeFrom(data []byte)` populates the block's string table, granularity, and coordinate offsets. Call `Groups()` to get a `GroupScanner`. String table entries are zero-copy slices into the block data — copy any strings you need to retain past the next `BlockReader.Next()` call.

- `String(i int) []byte` — look up a string table entry by index
- `Granularity` / `LatOffset` / `LonOffset` / `DateGranularity` — coordinate and timestamp conversion parameters

### GroupScanner

Iterates over `PrimitiveGroup` messages within a block. Call `Type()` to check the group kind, then use the appropriate decoder:

| GroupType | Decoder |
|---|---|
| `GroupTypeDense` | `gs.DecodeDenseNodes(&buf, info)` |
| `GroupTypeWays` | `gs.WayScanner()` |
| `GroupTypeRelations` | `gs.RelationScanner()` |
| `GroupTypeNodes` | `gs.NodeScanner()` |

### Buffer types

| Type | Fields | Notes |
|---|---|---|
| `DenseNodesBuf` | `IDs`, `Lats`, `Lons`, `KeysVals` | Parallel arrays; delta-decoded in-place |
| `WayBuf` | `Keys`, `Vals`, `Refs` | `Refs` are absolute node IDs (delta-decoded) |
| `RelationBuf` | `Keys`, `Vals`, `RolesSID`, `MemIDs`, `Types` | `MemIDs` absolute (delta-decoded) |
| `NodeBuf` | `Keys`, `Vals` | Individual nodes (rare in practice) |
| `InfoBuf` | `Version`, `Timestamp`, `Changeset`, `UID`, `UserSID`, `Visible` | Per-entity metadata |
| `DenseInfoBuf` | `Versions`, `Timestamps`, `Changesets`, `UIDs`, `UserSIDs`, `Visibles` | Per-node metadata arrays |

Pass `nil` for the info parameter to skip metadata decoding.

## Coordinate conversion

The library returns raw integers. Convert to nanodegrees using the block's parameters:

```go
lat_nanodeg := dnBuf.Lats[i]*int64(pb.Granularity) + pb.LatOffset
lon_nanodeg := dnBuf.Lons[i]*int64(pb.Granularity) + pb.LonOffset
```

Default granularity is 100 nanodegrees. Default offsets are 0.

To get degrees, divide by 1e9:

```go
latDeg := float64(lat_nanodeg) / 1e9
lonDeg := float64(lon_nanodeg) / 1e9
```

## Tag decoding

Tags are pairs of string-table indices. For ways and relations, `Keys` and `Vals` are parallel arrays:

```go
for i := range wBuf.Keys {
    key := pb.String(int(wBuf.Keys[i]))
    val := pb.String(int(wBuf.Vals[i]))
    fmt.Printf("%s = %s\n", key, val)
}
```

For dense nodes, tags are packed into a flat `KeysVals` array with `0` delimiters between nodes:

```go
j := 0
for i := range dnBuf.IDs {
    for j < len(dnBuf.KeysVals) && dnBuf.KeysVals[j] != 0 {
        key := pb.String(int(dnBuf.KeysVals[j]))
        val := pb.String(int(dnBuf.KeysVals[j+1]))
        j += 2
        fmt.Printf("node %d: %s = %s\n", dnBuf.IDs[i], key, val)
    }
    j++ // skip the 0 delimiter
}
```

## Metadata

Pass an `InfoBuf` or `DenseInfoBuf` to decode version, timestamp, changeset, and user metadata. Pass `nil` to skip it.

For ways and relations:

```go
var iBuf osmbr.InfoBuf
for id, ok := ws.Next(&wBuf, &iBuf); ok; id, ok = ws.Next(&wBuf, &iBuf) {
    fmt.Printf("way %d: v%d changeset=%d user=%s\n",
        id, iBuf.Version, iBuf.Changeset, pb.String(int(iBuf.UserSID)))
}
```

For dense nodes:

```go
var diBuf osmbr.DenseInfoBuf
gs.DecodeDenseNodes(&dnBuf, &diBuf)
for i, id := range dnBuf.IDs {
    ts := diBuf.Timestamps[i] * int64(pb.DateGranularity) // milliseconds since epoch
    fmt.Printf("node %d: v%d ts=%d\n", id, diBuf.Versions[i], ts)
}
```

## Non-goals

This library intentionally does not provide:

- **Domain types** — No `Node`/`Way`/`Relation` structs. Build your own from the buffer fields.
- **Filtering** — All entities in a block are decoded. Skip what you don't need in your loop.
- **Concurrency** — Single-threaded. Parallelize at the block level in your own code.
- **Header decoding** — `OSMHeader` blocks are identified by `BlockReader.Type()` but not decoded.
- **Semantic conversion** — Coordinates stay as raw integers; timestamps stay as raw values. The caller applies the conversion.

## Acknowledgments

Inspired by [tidwall/osmfile](https://github.com/tidwall/osmfile).
