package osmbr_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/invisiblefunnel/osmbr"
)

// The decoding API is single-goroutine by design: every buffer is caller-owned
// and the reader hands blobs off through NextInto. These tests run that
// contract the way a real consumer does — one producer filling pooled buffers,
// N workers decoding them — so `go test -race` has a concurrent execution to
// inspect. Correctness is checked by comparing against a serial decode of the
// same file: worker count must not change a single decoded value.

// tally accumulates order-independent sums over everything a block decodes,
// including the optional metadata buffers. Summing rather than recording
// sequences keeps the result independent of the order workers finish in, while
// still changing if any field decodes into the wrong entity.
type tally struct {
	blocks, nodes, ways, relations int64
	ids, coords, tags, refs        int64
	members, roles                 int64
	versions, timestamps           int64
	changesets, uids, userSIDs     int64
	visibles                       int64
}

func (t *tally) add(o tally) {
	t.blocks += o.blocks
	t.nodes += o.nodes
	t.ways += o.ways
	t.relations += o.relations
	t.ids += o.ids
	t.coords += o.coords
	t.tags += o.tags
	t.refs += o.refs
	t.members += o.members
	t.roles += o.roles
	t.versions += o.versions
	t.timestamps += o.timestamps
	t.changesets += o.changesets
	t.uids += o.uids
	t.userSIDs += o.userSIDs
	t.visibles += o.visibles
}

// decodeBufs is one worker's private decoding state: the whole set of
// caller-owned buffers the API expects to be reused across blocks.
type decodeBufs struct {
	dec   osmbr.Decompressor
	pb    osmbr.PrimitiveBlock
	dnBuf osmbr.DenseNodesBuf
	diBuf osmbr.DenseInfoBuf
	nBuf  osmbr.NodeBuf
	wBuf  osmbr.WayBuf
	rBuf  osmbr.RelationBuf
	iBuf  osmbr.InfoBuf
}

// decodeBlob decompresses and fully decodes one OSMData blob, requesting every
// optional metadata buffer so the Info and DenseInfo paths are exercised too.
func (b *decodeBufs) decodeBlob(blob []byte) (tally, error) {
	var t tally

	data, err := b.dec.Decompress(blob)
	if err != nil {
		return t, err
	}
	if err := b.pb.DecodeFrom(data); err != nil {
		return t, err
	}
	t.blocks = 1

	gs := b.pb.Groups()
	for gs.Next() {
		switch gs.Type() {
		case osmbr.GroupTypeDense:
			if err := gs.DecodeDenseNodes(&b.dnBuf, &b.diBuf); err != nil {
				return t, err
			}
			t.nodes += int64(len(b.dnBuf.IDs))
			for i, id := range b.dnBuf.IDs {
				t.ids += id
				t.coords += b.dnBuf.Lats[i] + b.dnBuf.Lons[i]
			}
			for _, kv := range b.dnBuf.KeysVals {
				t.tags += int64(kv)
			}
			t.addDenseInfo(&b.diBuf)

		case osmbr.GroupTypeNodes:
			ns := gs.NodeScanner()
			for {
				id, lat, lon, ok := ns.Next(&b.nBuf, &b.iBuf)
				if !ok {
					break
				}
				t.nodes++
				t.ids += id
				t.coords += lat + lon
				t.addTags(b.nBuf.Keys, b.nBuf.Vals)
				t.addInfo(&b.iBuf)
			}

		case osmbr.GroupTypeWays:
			ws := gs.WayScanner()
			for {
				id, ok := ws.Next(&b.wBuf, &b.iBuf)
				if !ok {
					break
				}
				t.ways++
				t.ids += id
				t.addTags(b.wBuf.Keys, b.wBuf.Vals)
				for _, ref := range b.wBuf.Refs {
					t.refs += ref
				}
				t.addInfo(&b.iBuf)
			}

		case osmbr.GroupTypeRelations:
			rs := gs.RelationScanner()
			for {
				id, ok := rs.Next(&b.rBuf, &b.iBuf)
				if !ok {
					break
				}
				t.relations++
				t.ids += id
				t.addTags(b.rBuf.Keys, b.rBuf.Vals)
				for i, mem := range b.rBuf.MemIDs {
					t.members += mem + int64(b.rBuf.Types[i])
					t.roles += int64(b.rBuf.RolesSID[i])
				}
				t.addInfo(&b.iBuf)
			}
		}
	}
	return t, gs.Err()
}

func (t *tally) addTags(keys, vals []uint32) {
	for i, k := range keys {
		t.tags += int64(k) + int64(vals[i])
	}
}

func (t *tally) addInfo(info *osmbr.InfoBuf) {
	t.versions += int64(info.Version)
	t.timestamps += info.Timestamp
	t.changesets += info.Changeset
	t.uids += int64(info.UID)
	t.userSIDs += int64(info.UserSID)
	if info.HasVisible && info.Visible {
		t.visibles++
	}
}

func (t *tally) addDenseInfo(info *osmbr.DenseInfoBuf) {
	for _, v := range info.Versions {
		t.versions += int64(v)
	}
	for _, ts := range info.Timestamps {
		t.timestamps += ts
	}
	for _, cs := range info.Changesets {
		t.changesets += cs
	}
	for _, uid := range info.UIDs {
		t.uids += int64(uid)
	}
	for _, sid := range info.UserSIDs {
		t.userSIDs += int64(sid)
	}
	for _, v := range info.Visibles {
		if v {
			t.visibles++
		}
	}
}

// decodeSerial decodes the whole file in one goroutine: the baseline every
// concurrent run must reproduce exactly.
func decodeSerial(t *testing.T) tally {
	t.Helper()

	f := openTestPBF(t)
	var (
		bufs  decodeBufs
		total tally
	)
	br := osmbr.NewBlockReader(f)
	for blob, ok := br.NextInto(nil); ok; blob, ok = br.NextInto(blob[:0]) {
		if br.Type() != "OSMData" {
			continue
		}
		got, err := bufs.decodeBlob(blob)
		if err != nil {
			t.Fatalf("serial decode: %v", err)
		}
		total.add(got)
	}
	if err := br.Err(); err != nil {
		t.Fatalf("serial BlockReader: %v", err)
	}
	return total
}

// decodeConcurrent mirrors examples/count: a producer reading blobs into
// pooled, caller-owned buffers and workers decoding them in parallel, each
// with its own decompressor and buffer set.
func decodeConcurrent(t *testing.T, workers int) tally {
	t.Helper()

	f := openTestPBF(t)
	var (
		pool    sync.Pool
		jobs    = make(chan []byte, workers)
		results = make(chan tally, workers)
		wg      sync.WaitGroup
	)

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var bufs decodeBufs
			for blob := range jobs {
				got, err := bufs.decodeBlob(blob)
				if err != nil {
					t.Errorf("worker decode: %v", err)
				}
				pool.Put(blob[:0]) //nolint:staticcheck // SA6002: the pool holds slices by design
				results <- got
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var readErr error
	go func() {
		defer close(jobs)
		br := osmbr.NewBlockReader(f)
		for {
			buf, _ := pool.Get().([]byte)
			blob, ok := br.NextInto(buf)
			if !ok {
				pool.Put(blob[:0])
				break
			}
			if br.Type() != "OSMData" {
				pool.Put(blob[:0])
				continue
			}
			jobs <- blob
		}
		readErr = br.Err()
	}()

	var total tally
	for got := range results {
		total.add(got)
	}
	// close(jobs) happens-before the workers' final receive, which happens-before
	// wg.Wait, close(results), and this drain — so readErr is safely visible here.
	if readErr != nil {
		t.Fatalf("concurrent BlockReader: %v", readErr)
	}
	return total
}

func TestConcurrentDecodeMatchesSerial(t *testing.T) {
	want := decodeSerial(t)

	// Guard against a vacuous comparison: if the fixture decoded nothing, or
	// carried no metadata, matching tallies would prove nothing. Only versions
	// and timestamps are checked — the bundled extract is anonymized, so its
	// changeset and uid arrays are present but filled with zeros.
	switch {
	case want.blocks == 0 || want.nodes == 0 || want.ways == 0 || want.relations == 0:
		t.Fatalf("fixture decoded no entities: %+v", want)
	case want.versions == 0 || want.timestamps == 0:
		t.Fatalf("fixture carried no metadata, info paths untested: %+v", want)
	}

	for _, workers := range []int{1, 2, 4, 8, 16} {
		t.Run(fmt.Sprintf("workers=%d", workers), func(t *testing.T) {
			if got := decodeConcurrent(t, workers); got != want {
				t.Errorf("concurrent decode differs from serial\n got: %+v\nwant: %+v", got, want)
			}
		})
	}
}
