# osmbr

A low-level Go library for reading OpenStreetMap [PBF files](https://wiki.openstreetmap.org/wiki/PBF_Format). Designed for minimal allocation and caller-controlled memory.

## Design

- **Caller-managed buffers** — Allocate buffer structs once and reuse them across blocks. After warm-up, reading a whole file makes zero heap allocations.
- **Scanner-style APIs** — Sequential reads with sticky errors checked after iteration.
- **Raw values** — Returns raw integers for coordinates and string-table indices for tags. The caller applies granularity/offset conversion.
- **No domain types** — There are no `Node`, `Way`, or `Relation` structs. The caller reads fields from buffer structs and builds whatever representation it needs.

Protobuf decoding is done in-package against the PBF schema, so the only
dependency is [klauspost/compress](https://github.com/klauspost/compress) for
DEFLATE.

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
    dec   osmbr.Decompressor
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
    data, err := dec.Decompress(br.Blob())
    if err != nil {
        log.Fatal(err)
    }
    if err := pb.DecodeFrom(data); err != nil {
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
    if err := gs.Err(); err != nil {
        log.Fatal(err)
    }
}
if err := br.Err(); err != nil {
    log.Fatal(err)
}
```

## API overview

The reading pipeline flows top-down:

### BlockReader

`NewBlockReader(r io.Reader)` reads PBF file blocks sequentially. Call `Next()` to advance, then `Type()` for the block type (`"OSMHeader"` or `"OSMData"`) and `Blob()` for the raw Blob protobuf bytes. `Blob()` points into the reader's own storage and is invalidated by the next read. Use a `Decompressor` to decompress it.

Errors stop the walk for good: a failed read leaves the stream parked mid-block, where the following bytes are payload rather than a length prefix, so every later `Next()` reports false and `Err()` keeps returning that first failure until you `Reset`.

The zero value is ready to use after `Reset(r)`, so a `BlockReader` can live inside a struct you already own:

```go
type worker struct {
    br  osmbr.BlockReader
    dec osmbr.Decompressor
}

func (w *worker) run(r io.Reader) {
    w.br.Reset(r)
    for w.br.Next() {
        // ...
    }
}
```

`Reset` also lets one reader walk many files without reallocating.

#### Handing blocks to other goroutines

When a blob must outlive the next read — a producer feeding worker goroutines, say — use `NextInto(dst []byte) ([]byte, bool)` instead. It reads directly into caller-owned storage, allocating a larger slice only when `cap(dst)` is too small, so the returned slice may not share storage with `dst`; retain the returned one. On EOF or error it returns `dst[:0]`, so a pooled buffer is never lost.

```go
var pool sync.Pool
br := osmbr.NewBlockReader(f)
for {
    buf, _ := pool.Get().([]byte)
    blob, ok := br.NextInto(buf)
    if !ok {
        pool.Put(blob) // dst[:0] — nothing lost
        break
    }
    if br.Type() != "OSMData" {
        pool.Put(blob[:0])
        continue
    }
    jobs <- blob // worker returns blob[:0] to pool when done
}
if err := br.Err(); err != nil {
    log.Fatal(err)
}
```

See `examples/count` for the full producer/worker pattern.

### Header

`DecodeHeader(data []byte)` decodes a decompressed `OSMHeader` block, returning a `Header` with the bounding box, required/optional features, writing program, source, and replication metadata.

### Decompressor

`Decompress(blob []byte)` parses and decompresses a raw Blob message, returning the decompressed payload. Allocate one per goroutine and reuse across blocks. The returned slice points into the `Decompressor`'s own storage and is valid until the next `Decompress` call — including for uncompressed (`raw`) blobs, which are copied rather than aliased so that advancing the `BlockReader` can never rewrite a payload you still hold.

osmbr reads the zlib wrapper itself and drives [klauspost/compress](https://github.com/klauspost/compress)'s DEFLATE reader directly, reusing its state across blocks.

Every zlib blob's Adler-32 trailer is **verified by default**, which costs about 14% of decompression time (~10% of a whole-file read). Inflating rejects most corruption on its own and `Decompress` independently requires the output to end exactly at `Blob.raw_size`, but neither covers a stored (uncompressed) DEFLATE block: a flipped bit there changes neither the stream's structure nor its length, so the checksum is the only thing that catches it. Skip the check only for input whose integrity is already assured:

```go
dec := osmbr.Decompressor{SkipChecksum: true}
```

Note the `raw_size` length check applies only when `Blob.raw_size` is present. Without it, output is bounded by the 32 MiB blob limit and nothing else.

Only `raw` and `zlib_data` blobs are supported; lzma, bzip2, lz4, and zstd blobs return an error.

### PrimitiveBlock

`DecodeFrom(data []byte)` populates the block's string table, granularity, and coordinate offsets from decompressed block data. Call `Groups()` to get a `GroupScanner`. String table entries are zero-copy slices into the data — copy any strings you need to retain past the next `Decompress` call.

- `String(i int) []byte` — look up a string table entry by index
- `Granularity` / `LatOffset` / `LonOffset` / `DateGranularity` — coordinate and timestamp conversion parameters

### GroupScanner

Iterates over `PrimitiveGroup` messages within a block. Call `Type()` to check the group kind, then use the appropriate decoder. Check `Err()` after iteration finishes to distinguish error from EOF.

| GroupType | Decoder |
|---|---|
| `GroupTypeDense` | `gs.DecodeDenseNodes(&buf, info)` |
| `GroupTypeWays` | `gs.WayScanner()` |
| `GroupTypeRelations` | `gs.RelationScanner()` |
| `GroupTypeNodes` | `gs.NodeScanner()` |

### Buffer types

| Type | Fields | Notes |
|---|---|---|
| `DenseNodesBuf` | `IDs`, `Lats`, `Lons`, `KeysVals` | Parallel arrays; `IDs`/`Lats`/`Lons` are absolute (delta-decoded) |
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

## Performance

Measured on the bundled 3.1 MB extract (Go 1.26, arm64), reading every block through decompression and full entity decode, with Adler-32 verification at its default setting:

| | time/op | allocs/op |
|---|---|---|
| Whole file, no metadata | ~23 ms | 0 |
| Whole file, with metadata | ~25 ms | 0 |

Timings drift a few percent between runs on the same machine, so treat them as a scale rather than a target; the allocation counts are exact.

Decompression accounts for roughly 79% of the total, and the rest is protobuf decode. Checksum verification is about 14% of the decompression figure, so `SkipChecksum: true` takes a whole-file read down to roughly 21 ms / 23 ms. Reproduce with:

```
go test -bench=. -benchmem -run=^$ .
```

The benchmark suite has two tiers: micro-benchmarks over synthetic inputs that isolate each hot path, and end-to-end benchmarks over the bundled extract. Use [benchstat](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat) to compare runs.

## Non-goals

This library intentionally does not provide:

- **Domain types** — No `Node`/`Way`/`Relation` structs. Build your own from the buffer fields.
- **Filtering** — All entities in a block are decoded. Skip what you don't need in your loop.
- **Concurrency** — Single-threaded. Parallelize at the block level in your own code.
- **Semantic conversion** — Coordinates stay as raw integers; timestamps stay as raw values. The caller applies the conversion.

## Acknowledgments

Inspired by [tidwall/osmfile](https://github.com/tidwall/osmfile).

Portions of the implementation, tests, and documentation were developed with the assistance of [Claude Code](https://claude.com/claude-code).
