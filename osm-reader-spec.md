# OSM PBF Block Reader — Specification

A Go library for reading OpenStreetMap PBF files. It reads and decompresses file blocks, decodes protobuf wire data into caller-provided buffers, and performs delta decoding — but does not construct domain objects or convert coordinate units. The caller decides what to build from the raw fields.

## Design goals

1. **Minimal allocation.** The caller provides buffer structs. The library resets them (preserving capacity) and appends into them on each decode call. After the first few blocks, no heap allocations should occur in the hot path.

2. **Minimal semantic conversion.** Coordinates are returned as raw integers. The caller applies granularity and offset to get nanodegrees. Tags are returned as string-table indices, not resolved strings. Timestamps are raw integers. The library decodes the wire format — nothing more.

3. **Caller-managed memory.** Every slice that holds decoded data lives in a struct the caller allocates, reuses, and controls the lifetime of. The library never allocates slices on behalf of the caller.

4. **Zero-copy where possible.** String table entries and intermediate proto message bytes should reference the underlying block data without copying. Document clearly when a reference becomes invalid (e.g., on the next block advance).

5. **Scanner pattern.** Iteration follows the `for scanner.Next() { ... }` idiom. Errors are sticky — check `Err()` after the loop, not on every call.

## Dependencies

- **`paulmach/protoscan`** for protobuf wire-format decoding. This library provides a `Message` scanner that reads fields one at a time without code generation or full message unmarshaling. It supports zero-copy `Bytes()`, buffer-reusing `RepeatedSint64(buf)`, and field skipping.

- **`klauspost/compress`** for zlib decompression, replacing the standard library `compress/zlib`. It reuses internal decompressor state across `Reset` calls, which eliminates the per-block allocation overhead inherent in `compress/flate`.

No other external dependencies.

## PBF file structure

An OSM PBF file is a sequence of **file blocks**. Each file block is:

1. A 4-byte big-endian uint32: the byte length of the serialized BlobHeader.
2. The serialized **BlobHeader** protobuf message.
3. The serialized **Blob** protobuf message (whose length is given by BlobHeader.datasize).

### BlobHeader fields

| Field | Number | Wire type | Description |
|-------|--------|-----------|-------------|
| type | 1 | string | `"OSMHeader"` or `"OSMData"` |
| datasize | 3 | int32 | Byte length of the following Blob message |

### Blob fields

| Field | Number | Wire type | Description |
|-------|--------|-----------|-------------|
| raw | 1 | bytes | Uncompressed payload |
| raw_size | 2 | int32 | Decompressed size (when compressed) |
| zlib_data | 3 | bytes | Zlib-compressed payload |

Exactly one of `raw` or `zlib_data` is present. Fields 4 (lzma) and 5 (bzip2) exist in the spec but are effectively unused; the library should reject them.

### PrimitiveBlock fields

The decompressed payload of an `"OSMData"` block.

| Field | Number | Wire type | Description |
|-------|--------|-----------|-------------|
| stringtable | 1 | message | Contains repeated bytes `s` (field 1) |
| primitivegroup | 2 | repeated message | One or more groups of homogeneous entities |
| granularity | 17 | int32 | Coordinate resolution in nanodegrees; default 100 |
| date_granularity | 18 | int32 | Timestamp resolution in milliseconds; default 1000 |
| lat_offset | 19 | int64 | Latitude offset in nanodegrees; default 0 |
| lon_offset | 20 | int64 | Longitude offset in nanodegrees; default 0 |

**Coordinate conversion** (performed by the caller, not the library):

```
lat_nanodegrees = raw_lat * granularity + lat_offset
lon_nanodegrees = raw_lon * granularity + lon_offset
```

### PrimitiveGroup fields

Each group contains exactly one entity type.

| Field | Number | Wire type | Description |
|-------|--------|-----------|-------------|
| nodes | 1 | repeated message | Individual Node messages (rare) |
| dense | 2 | message | DenseNodes columnar encoding (common) |
| ways | 3 | repeated message | Way messages |
| relations | 4 | repeated message | Relation messages |
| changesets | 5 | repeated message | Changeset messages (rare; no decoder needed) |

The library determines the group type by peeking at the first field number.

### DenseNodes fields

| Field | Number | Wire type | Description |
|-------|--------|-----------|-------------|
| id | 1 | packed sint64 | Delta-encoded node IDs |
| denseinfo | 5 | message | Optional per-node metadata (see DenseInfo) |
| lat | 8 | packed sint64 | Delta-encoded raw latitudes |
| lon | 9 | packed sint64 | Delta-encoded raw longitudes |
| keys_vals | 10 | packed int32 | Flat tag array: `(key_sid val_sid)* 0` per node |

After decoding, IDs, lats, and lons must be delta-decoded in place: `s[i] += s[i-1]` for `i` from 1 to len-1.

The `keys_vals` array encodes each node's tags as alternating key/value string-table indices, terminated by a `0` delimiter. Nodes with no tags contribute just a `0`.

### Way fields

| Field | Number | Wire type | Description |
|-------|--------|-----------|-------------|
| id | 1 | int64 | Way ID |
| keys | 2 | packed uint32 | Tag key string-table indices |
| vals | 3 | packed uint32 | Tag value string-table indices |
| info | 4 | message | Optional metadata (see Info) |
| refs | 8 | packed sint64 | Delta-encoded referenced node IDs |

### Relation fields

| Field | Number | Wire type | Description |
|-------|--------|-----------|-------------|
| id | 1 | int64 | Relation ID |
| keys | 2 | packed uint32 | Tag key string-table indices |
| vals | 3 | packed uint32 | Tag value string-table indices |
| info | 4 | message | Optional metadata (see Info) |
| roles_sid | 8 | packed int32 | Member role string-table indices |
| memids | 9 | packed sint64 | Delta-encoded member entity IDs |
| types | 10 | packed int32 | Member types: 0=node, 1=way, 2=relation |

### Node fields (non-dense)

| Field | Number | Wire type | Description |
|-------|--------|-----------|-------------|
| id | 1 | sint64 | Node ID |
| keys | 2 | packed uint32 | Tag key string-table indices |
| vals | 3 | packed uint32 | Tag value string-table indices |
| info | 4 | message | Optional metadata (see Info) |
| lat | 8 | sint64 | Raw latitude |
| lon | 9 | sint64 | Raw longitude |

### Info fields (per-entity metadata)

| Field | Number | Wire type | Description |
|-------|--------|-----------|-------------|
| version | 1 | int32 | Entity version |
| timestamp | 2 | int64 | Milliseconds since Unix epoch |
| changeset | 3 | int64 | Changeset ID |
| uid | 4 | int32 | User ID |
| user_sid | 5 | uint32 | Username string-table index |
| visible | 6 | bool | Visibility flag (may be absent) |

### DenseInfo fields (per-node metadata arrays)

| Field | Number | Wire type | Delta-encoded? | Description |
|-------|--------|-----------|----------------|-------------|
| version | 1 | packed int32 | No | Entity versions |
| timestamp | 2 | packed int64 | Yes | Milliseconds since Unix epoch |
| changeset | 3 | packed int64 | Yes | Changeset IDs |
| uid | 4 | packed int32 | Yes | User IDs |
| user_sid | 5 | packed uint32 | No | Username string-table indices |
| visible | 6 | packed bool | No | Visibility flags |

## API shape

The types and function signatures below define the public contract. Names are normative. Field types are normative. Internal implementation details (struct fields, helper functions) are not specified.

### Block reader

```go
// Reads and decompresses PBF file blocks sequentially from an io.Reader.
// Not safe for concurrent use.
type BlockReader struct { /* unexported */ }

func NewBlockReader(r io.Reader) *BlockReader
func (br *BlockReader) Next() bool      // advance to next block; false on EOF or error
func (br *BlockReader) Err() error      // first non-EOF error, or nil
func (br *BlockReader) Type() string    // "OSMHeader" or "OSMData"
func (br *BlockReader) Data() []byte    // decompressed proto bytes; valid until next Next()
```

Internal buffers (for BlobHeader bytes, Blob bytes, and decompressed output) are grown as needed and reused across blocks. The zlib decompressor is created once and reset on each block.

### PrimitiveBlock

```go
// Holds decoded block metadata and string table. Reusable across blocks.
type PrimitiveBlock struct {
    Granularity     int32  // nanodegrees; default 100
    LatOffset       int64  // nanodegrees; default 0
    LonOffset       int64  // nanodegrees; default 0
    DateGranularity int32  // milliseconds; default 1000
    // unexported: string table, retained block data
}

func (pb *PrimitiveBlock) DecodeFrom(data []byte) error  // populate from Data(); resets to defaults first
func (pb *PrimitiveBlock) String(i int) []byte            // zero-copy string table entry
func (pb *PrimitiveBlock) NumStrings() int
func (pb *PrimitiveBlock) Groups() GroupScanner           // iterate PrimitiveGroups
```

String table entries are zero-copy slices into the data passed to `DecodeFrom`. They are invalid after the next `DecodeFrom` or `BlockReader.Next` call. The caller must copy any entries it needs to retain.

`Groups()` returns a value-type scanner that re-reads group fields from the retained block data. Groups are not materialized eagerly — calling `Groups()` does not decode any entities.

### Group scanner

```go
type GroupType int8

const (
    GroupTypeUnknown    GroupType = 0
    GroupTypeNodes      GroupType = 1
    GroupTypeDense      GroupType = 2
    GroupTypeWays       GroupType = 3
    GroupTypeRelations  GroupType = 4
    GroupTypeChangesets GroupType = 5
)

// Iterates PrimitiveGroups within a block. Value type.
type GroupScanner struct { /* unexported */ }

func (gs *GroupScanner) Next() bool           // advance to next group
func (gs *GroupScanner) Type() GroupType       // type of current group

func (gs *GroupScanner) DecodeDenseNodes(buf *DenseNodesBuf, info *DenseInfoBuf) error
func (gs *GroupScanner) WayScanner() WayScanner
func (gs *GroupScanner) RelationScanner() RelationScanner
func (gs *GroupScanner) NodeScanner() NodeScanner
```

`DecodeDenseNodes` decodes the entire DenseNodes group into the caller's buffer in one call. The other methods return value-type scanners for iterating individual entities within the group.

### Entity buffers

All buffer structs are allocated and owned by the caller. On each decode call, every slice is reset to `[:0]` (preserving backing array capacity) before appending new data. After the first few blocks, slice capacities stabilize and no further allocation occurs.

```go
type DenseNodesBuf struct {
    IDs      []int64   // delta-decoded absolute node IDs
    Lats     []int64   // delta-decoded raw latitudes
    Lons     []int64   // delta-decoded raw longitudes
    KeysVals []int32   // flat tag array: (key_sid val_sid)* 0 per node
}

type WayBuf struct {
    Keys []uint32  // tag key string-table indices
    Vals []uint32  // tag value string-table indices
    Refs []int64   // delta-decoded absolute referenced node IDs
}

type RelationBuf struct {
    Keys     []uint32  // tag key string-table indices
    Vals     []uint32  // tag value string-table indices
    RolesSID []int32   // member role string-table indices
    MemIDs   []int64   // delta-decoded absolute member IDs
    Types    []int32   // member types: 0=node, 1=way, 2=relation
}

type NodeBuf struct {
    Keys []uint32  // tag key string-table indices
    Vals []uint32  // tag value string-table indices
}
```

### Entity scanners

Each scanner iterates over repeated entity messages within a single PrimitiveGroup. They are value types returned from GroupScanner methods.

```go
type WayScanner struct { /* unexported */ }
func (ws *WayScanner) Next(buf *WayBuf, info *InfoBuf) (id int64, ok bool)
func (ws *WayScanner) Err() error

type RelationScanner struct { /* unexported */ }
func (rs *RelationScanner) Next(buf *RelationBuf, info *InfoBuf) (id int64, ok bool)
func (rs *RelationScanner) Err() error

type NodeScanner struct { /* unexported */ }
func (ns *NodeScanner) Next(buf *NodeBuf, info *InfoBuf) (id, lat, lon int64, ok bool)
func (ns *NodeScanner) Err() error
```

The `info` parameter is optional. Pass `nil` to skip metadata decoding entirely (the Info field is not even read from the wire). Pass a non-nil pointer to populate it.

### Metadata buffers

```go
// Per-entity metadata. Passed as optional *InfoBuf to entity scanner Next methods.
type InfoBuf struct {
    Version    int32
    Timestamp  int64   // milliseconds since Unix epoch
    Changeset  int64
    UID        int32
    UserSID    uint32  // string table index
    Visible    bool
    HasVisible bool    // false if the visible field was absent in the proto
}

// Per-node metadata arrays for DenseNodes. Passed as optional *DenseInfoBuf to DecodeDenseNodes.
type DenseInfoBuf struct {
    Versions   []int32   // not delta-encoded
    Timestamps []int64   // delta-decoded
    Changesets []int64   // delta-decoded
    UIDs       []int32   // delta-decoded
    UserSIDs   []uint32  // not delta-encoded; string table indices
    Visibles   []bool
}
```

### Member type constants

```go
const (
    MemberTypeNode     = int32(0)
    MemberTypeWay      = int32(1)
    MemberTypeRelation = int32(2)
)
```

## Usage pattern

```go
br := NewBlockReader(f)
var pb PrimitiveBlock
var dnBuf DenseNodesBuf
var wBuf WayBuf
var rBuf RelationBuf

for br.Next() {
    if br.Type() != "OSMData" {
        continue
    }
    pb.DecodeFrom(br.Data())

    gs := pb.Groups()
    for gs.Next() {
        switch gs.Type() {
        case GroupTypeDense:
            gs.DecodeDenseNodes(&dnBuf, nil)
            for i, id := range dnBuf.IDs {
                lat := dnBuf.Lats[i]*int64(pb.Granularity) + pb.LatOffset
                lon := dnBuf.Lons[i]*int64(pb.Granularity) + pb.LonOffset
                _ = id; _ = lat; _ = lon
            }
        case GroupTypeWays:
            ws := gs.WayScanner()
            for id, ok := ws.Next(&wBuf, nil); ok; id, ok = ws.Next(&wBuf, nil) {
                _ = id
            }
        case GroupTypeRelations:
            rs := gs.RelationScanner()
            for id, ok := rs.Next(&rBuf, nil); ok; id, ok = rs.Next(&rBuf, nil) {
                _ = id
            }
        }
    }
}
if err := br.Err(); err != nil {
    // handle error
}
```

All buffers are declared once outside the loop and reused for every block, group, and entity.

## Error handling

- `BlockReader.Next` returns `false` on both EOF and error. `Err()` returns `nil` for clean EOF.
- Entity scanner `Next` methods return `ok=false` when iteration is complete or on error. `Err()` returns the first error, if any.
- Errors are sticky: once set, further `Next` calls return `false` immediately.

## What the library does not do

- **No domain types.** It does not define Node, Way, or Relation structs. The caller builds whatever representation it needs from the buffer contents.
- **No coordinate conversion.** Lat/lon stay as raw integers. The formula is documented; the caller applies it.
- **No string resolution.** Tags are pairs of string-table indices. The caller calls `PrimitiveBlock.String(i)` to look them up.
- **No filtering.** Every entity in every group is decoded. The caller skips what it doesn't need by not calling the relevant scanner.
- **No concurrency.** The block reader is single-threaded. Parallelism (e.g., concurrent decompression) is left to the caller or a higher-level wrapper.
- **No HeaderBlock decoding.** `"OSMHeader"` blocks are surfaced by the block reader but no decoder is provided. The caller skips them or decodes them externally.
