package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

type RollupRow struct {
	Minute          int64  `json:"minute"`
	Client          string `json:"client"`
	Category        string `json:"category"`
	Target          string `json:"target"`
	Proto           string `json:"proto"`
	Port            uint16 `json:"port"`
	DownloadBytes   uint64 `json:"download_bytes"`
	UploadBytes     uint64 `json:"upload_bytes"`
	DownloadPackets uint64 `json:"download_packets"`
	UploadPackets   uint64 `json:"upload_packets"`
}

type RollupTotal struct {
	Minute          int64
	Name            string
	DownloadBytes   uint64
	UploadBytes     uint64
	DownloadPackets uint64
	UploadPackets   uint64
}

type RollupStore struct {
	path string
}

type TopAgg struct {
	Client, Category, Target, Proto string
	Port                            uint16
	Up, Down, UpP, DownP            uint64
}

// Read endpoints should fail fast while a writer/prune owns the bbolt flock.
// Waiting longer keeps canceled HTTP work alive and lets replacement requests
// pile up; the next UI refresh can retry once the exclusive operation is done.
const rollupReadOnlyTimeout = time.Second

// Pruning a large bbolt database in one transaction holds its process-wide
// flock for the entire scan. That makes every web read and capture flush fail
// until the scan completes. Keep each exclusive slice small and leave a brief
// gap between slices so readers and the flush path can make progress.
const (
	rollupPruneBatchKeys  = 2048
	rollupPruneBatchPause = 25 * time.Millisecond
)

type rollupPruneOptions struct {
	batchKeys  int
	pause      time.Duration
	afterBatch func()
}

// pruneRollup preserves the original single-retention API. New callers should
// use pruneRollupTiers to keep compact summaries longer than per-target detail.
func pruneRollup(path string, cutoff time.Time) (int, error) {
	detail, summary, err := pruneRollupTiers(path, cutoff, cutoff)
	return detail + summary, err
}

// pruneRollupTiers applies independent retention cutoffs to the large
// per-target bucket and the three compact summary buckets. A zero cutoff keeps
// that tier forever. The minute-prefixed buckets are key-sorted by minute, so
// scans stop at the cutoff; flow_client_category_minute_v1 is client-first and
// must be scanned in full. Cursor deletion avoids copying every expired key
// into RAM. bbolt reuses freed pages but does not shrink the file on disk.
func pruneRollupTiers(path string, summaryCutoff, detailCutoff time.Time) (detailDeleted, summaryDeleted int, err error) {
	return pruneRollupTiersWithOptions(path, summaryCutoff, detailCutoff, rollupPruneOptions{
		batchKeys: rollupPruneBatchKeys,
		pause:     rollupPruneBatchPause,
	})
}

func pruneRollupTiersWithOptions(path string, summaryCutoff, detailCutoff time.Time, opts rollupPruneOptions) (detailDeleted, summaryDeleted int, err error) {
	if summaryCutoff.IsZero() && detailCutoff.IsZero() {
		return 0, 0, nil
	}
	if opts.batchKeys <= 0 {
		opts.batchKeys = rollupPruneBatchKeys
	}

	if detailDeleted, err = pruneRollupBucketBatched(path, rollupBucket, detailCutoff, true, opts); err != nil {
		return detailDeleted, summaryDeleted, err
	}
	for _, bucket := range [][]byte{rollupClientBucket, rollupCategoryBucket} {
		deleted, pruneErr := pruneRollupBucketBatched(path, bucket, summaryCutoff, true, opts)
		summaryDeleted += deleted
		if pruneErr != nil {
			return detailDeleted, summaryDeleted, pruneErr
		}
	}
	deleted, err := pruneRollupBucketBatched(path, rollupClientCategoryBucket, summaryCutoff, false, opts)
	summaryDeleted += deleted
	return detailDeleted, summaryDeleted, err
}

func pruneRollupBucketBatched(path string, bucket []byte, cutoff time.Time, minuteFirst bool, opts rollupPruneOptions) (int, error) {
	if cutoff.IsZero() {
		return 0, nil
	}
	var after []byte
	totalDeleted := 0
	for {
		deleted, next, done, err := pruneRollupBucketBatch(path, bucket, cutoff.Unix()/60, minuteFirst, after, opts.batchKeys)
		totalDeleted += deleted
		if err != nil {
			return totalDeleted, err
		}
		// pruneRollupBucketBatch has closed the database at this point, so the
		// hook and pause both run without an exclusive flock.
		if opts.afterBatch != nil {
			opts.afterBatch()
		}
		if opts.pause > 0 {
			time.Sleep(opts.pause)
		}
		if done {
			return totalDeleted, nil
		}
		if len(next) == 0 {
			return totalDeleted, fmt.Errorf("rollup prune bucket %q made no progress", bucket)
		}
		after = next
	}
}

func pruneRollupBucketBatch(path string, bucket []byte, cutoffMinute int64, minuteFirst bool, after []byte, maxKeys int) (deleted int, next []byte, done bool, err error) {
	db, err := bolt.Open(path, 0644, &bolt.Options{Timeout: 30 * time.Second})
	if err != nil {
		return 0, nil, false, err
	}
	defer func() {
		if closeErr := db.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			done = true
			return nil
		}
		c := b.Cursor()
		k, _ := c.First()
		if len(after) > 0 {
			k, _ = c.Seek(after)
			if bytes.Equal(k, after) {
				k, _ = c.Next()
			}
		}
		processed := 0
		for ; k != nil && processed < maxKeys; k, _ = c.Next() {
			key := append([]byte(nil), k...)
			minute, valid := pruneRollupKeyMinute(k, minuteFirst)
			if minuteFirst && valid && minute >= cutoffMinute {
				done = true
				return nil
			}
			next = key
			processed++
			if valid && minute < cutoffMinute {
				if err := c.Delete(); err != nil {
					return err
				}
				deleted++
			}
		}
		if k == nil {
			done = true
		}
		return nil
	})
	return deleted, next, done, err
}

func pruneRollupKeyMinute(k []byte, minuteFirst bool) (int64, bool) {
	if minuteFirst {
		minute := minutePrefix(k)
		return minute, minute >= 0
	}
	parts := strings.SplitN(string(k), "\t", 3)
	if len(parts) != 3 {
		return 0, false
	}
	minute, err := strconv.ParseInt(parts[1], 10, 64)
	return minute, err == nil
}

// minutePrefix parses the leading zero-padded minute from a rollup key, or -1.
func minutePrefix(k []byte) int64 {
	s := string(k)
	if i := strings.IndexByte(s, '\t'); i >= 0 {
		s = s[:i]
	}
	m, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return -1
	}
	return m
}

var rollupBucket = []byte("flow_minute_v1")

var rollupClientBucket = []byte("flow_client_minute_v1")

var rollupCategoryBucket = []byte("flow_category_minute_v1")

var rollupClientCategoryBucket = []byte("flow_client_category_minute_v1")

type RollupClientCategoryTotal struct {
	Minute          int64
	Client          string
	Category        string
	DownloadBytes   uint64
	UploadBytes     uint64
	DownloadPackets uint64
	UploadPackets   uint64
}

func OpenRollup(path string) (*RollupStore, error) {
	return &RollupStore{path: path}, nil
}

func (r *RollupStore) Close() error {
	return nil
}

// maxPendingRollupRecords caps the in-memory retry queue for rollup writes.
// At the default 30s flush interval this is hours of failed flushes; past
// that, dropping the oldest records beats growing until the OOM killer fires.
const maxPendingRollupRecords = 200_000

// capPendingRollup drops the oldest records once the retry queue exceeds max.
// It copies the kept tail into a fresh slice so the dropped prefix does not
// pin the old backing array.
func capPendingRollup(pending []FlowRecord, max int) ([]FlowRecord, int) {
	if len(pending) <= max {
		return pending, 0
	}
	dropped := len(pending) - max
	kept := make([]FlowRecord, max)
	copy(kept, pending[dropped:])
	return kept, dropped
}

func (r *RollupStore) Add(records []FlowRecord) error {
	if r == nil || r.path == "" || len(records) == 0 {
		return nil
	}
	// Keep the lock wait short: Add runs on the flush path, and a stuck or
	// slow holder of the bbolt flock must not stall the daemon for long —
	// failed batches are retried from pendingRollup on the next flush.
	db, err := bolt.Open(r.path, 0644, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(rollupBucket)
		if err != nil {
			return err
		}
		clientTotals := map[string]*RollupTotal{}
		categoryTotals := map[string]*RollupTotal{}
		clientCategoryTotals := map[string]*RollupClientCategoryTotal{}
		for _, rec := range records {
			target := rec.Domain
			if target == "" {
				target = rec.RemoteIP
			}
			category := categorize(target, rec.RemoteIP, rec.Proto, rec.RemotePort)
			row := RollupRow{
				Minute:          rec.TSEnd.Unix() / 60,
				Client:          rec.Client,
				Category:        category,
				Target:          target,
				Proto:           rec.Proto,
				Port:            rec.RemotePort,
				DownloadBytes:   rec.ClientDownloadBytes,
				UploadBytes:     rec.ClientUploadBytes,
				DownloadPackets: rec.ClientDownloadPackets,
				UploadPackets:   rec.ClientUploadPackets,
			}
			addRollupTotal(clientTotals, row.Minute, row.Client, row.DownloadBytes, row.UploadBytes, row.DownloadPackets, row.UploadPackets)
			addRollupTotal(categoryTotals, row.Minute, row.Category, row.DownloadBytes, row.UploadBytes, row.DownloadPackets, row.UploadPackets)
			addRollupClientCategoryTotal(clientCategoryTotals, row.Minute, row.Client, row.Category, row.DownloadBytes, row.UploadBytes, row.DownloadPackets, row.UploadPackets)
			key := rollupKey(row)
			if old := b.Get(key); old != nil {
				var existing RollupRow
				if json.Unmarshal(old, &existing) == nil {
					row.DownloadBytes += existing.DownloadBytes
					row.UploadBytes += existing.UploadBytes
					row.DownloadPackets += existing.DownloadPackets
					row.UploadPackets += existing.UploadPackets
				}
			}
			raw, err := json.Marshal(row)
			if err != nil {
				return err
			}
			if err := b.Put(key, raw); err != nil {
				return err
			}
		}
		if err := putRollupTotals(tx, rollupClientBucket, clientTotals); err != nil {
			return err
		}
		if err := putRollupTotals(tx, rollupCategoryBucket, categoryTotals); err != nil {
			return err
		}
		if err := putRollupClientCategoryTotals(tx, clientCategoryTotals); err != nil {
			return err
		}
		return nil
	})
}

func rollupKey(row RollupRow) []byte {
	return []byte(fmt.Sprintf("%012d\t%s\t%s\t%s\t%s\t%d", row.Minute, row.Client, row.Category, row.Target, row.Proto, row.Port))
}

func rollupTotalKey(minute int64, name string) []byte {
	return []byte(fmt.Sprintf("%012d\t%s", minute, name))
}

func rollupClientCategoryKey(minute int64, client, category string) []byte {
	return []byte(fmt.Sprintf("%s\t%012d\t%s", client, minute, category))
}

func addRollupTotal(m map[string]*RollupTotal, minute int64, name string, down, up, downP, upP uint64) {
	key := fmt.Sprintf("%012d\t%s", minute, name)
	t := m[key]
	if t == nil {
		t = &RollupTotal{Minute: minute, Name: name}
		m[key] = t
	}
	t.DownloadBytes += down
	t.UploadBytes += up
	t.DownloadPackets += downP
	t.UploadPackets += upP
}

func addRollupClientCategoryTotal(m map[string]*RollupClientCategoryTotal, minute int64, client, category string, down, up, downP, upP uint64) {
	key := string(rollupClientCategoryKey(minute, client, category))
	t := m[key]
	if t == nil {
		t = &RollupClientCategoryTotal{Minute: minute, Client: client, Category: category}
		m[key] = t
	}
	t.DownloadBytes += down
	t.UploadBytes += up
	t.DownloadPackets += downP
	t.UploadPackets += upP
}

func putRollupTotals(tx *bolt.Tx, bucket []byte, totals map[string]*RollupTotal) error {
	if len(totals) == 0 {
		return nil
	}
	b, err := tx.CreateBucketIfNotExists(bucket)
	if err != nil {
		return err
	}
	for _, t := range totals {
		key := rollupTotalKey(t.Minute, t.Name)
		if old := b.Get(key); len(old) == 32 {
			existing := decodeRollupTotalValue(old)
			t.DownloadBytes += existing.DownloadBytes
			t.UploadBytes += existing.UploadBytes
			t.DownloadPackets += existing.DownloadPackets
			t.UploadPackets += existing.UploadPackets
		}
		if err := b.Put(key, encodeRollupTotalValue(t)); err != nil {
			return err
		}
	}
	return nil
}

func putRollupClientCategoryTotals(tx *bolt.Tx, totals map[string]*RollupClientCategoryTotal) error {
	if len(totals) == 0 {
		return nil
	}
	b, err := tx.CreateBucketIfNotExists(rollupClientCategoryBucket)
	if err != nil {
		return err
	}
	for _, t := range totals {
		key := rollupClientCategoryKey(t.Minute, t.Client, t.Category)
		if old := b.Get(key); len(old) == 32 {
			existing := decodeRollupTotalValue(old)
			t.DownloadBytes += existing.DownloadBytes
			t.UploadBytes += existing.UploadBytes
			t.DownloadPackets += existing.DownloadPackets
			t.UploadPackets += existing.UploadPackets
		}
		val := &RollupTotal{
			DownloadBytes:   t.DownloadBytes,
			UploadBytes:     t.UploadBytes,
			DownloadPackets: t.DownloadPackets,
			UploadPackets:   t.UploadPackets,
		}
		if err := b.Put(key, encodeRollupTotalValue(val)); err != nil {
			return err
		}
	}
	return nil
}

func encodeRollupTotalValue(t *RollupTotal) []byte {
	b := make([]byte, 32)
	binary.BigEndian.PutUint64(b[0:8], t.DownloadBytes)
	binary.BigEndian.PutUint64(b[8:16], t.UploadBytes)
	binary.BigEndian.PutUint64(b[16:24], t.DownloadPackets)
	binary.BigEndian.PutUint64(b[24:32], t.UploadPackets)
	return b
}

func decodeRollupTotalValue(b []byte) RollupTotal {
	if len(b) < 32 {
		return RollupTotal{}
	}
	return RollupTotal{
		DownloadBytes:   binary.BigEndian.Uint64(b[0:8]),
		UploadBytes:     binary.BigEndian.Uint64(b[8:16]),
		DownloadPackets: binary.BigEndian.Uint64(b[16:24]),
		UploadPackets:   binary.BigEndian.Uint64(b[24:32]),
	}
}

func aggregateReportTotalsFromRollup(path string, cutoff time.Time) (map[string]*TopAgg, map[string]*TopAgg, int, error) {
	return aggregateReportTotalsFromRollupContext(context.Background(), path, cutoff)
}

func aggregateReportTotalsFromRollupContext(ctx context.Context, path string, cutoff time.Time) (map[string]*TopAgg, map[string]*TopAgg, int, error) {
	byClient := map[string]*TopAgg{}
	byCategory := map[string]*TopAgg{}
	if err := ctx.Err(); err != nil {
		return byClient, byCategory, 0, err
	}
	db, err := bolt.Open(path, 0444, &bolt.Options{ReadOnly: true, Timeout: rollupReadOnlyTimeout})
	if err != nil {
		return byClient, byCategory, 0, err
	}
	defer db.Close()
	cutoffMinute := cutoff.Unix() / 60
	count := 0
	err = db.View(func(tx *bolt.Tx) error {
		n, err := readRollupTotalBucketContext(ctx, tx, rollupClientBucket, cutoffMinute, byClient, true)
		count += n
		if err != nil {
			return err
		}
		n, err = readRollupTotalBucketContext(ctx, tx, rollupCategoryBucket, cutoffMinute, byCategory, false)
		count += n
		if err != nil {
			return err
		}
		return nil
	})
	return byClient, byCategory, count, err
}

func readRollupTotalBucket(tx *bolt.Tx, bucket []byte, cutoffMinute int64, dst map[string]*TopAgg, client bool) int {
	n, _ := readRollupTotalBucketContext(context.Background(), tx, bucket, cutoffMinute, dst, client)
	return n
}

func readRollupTotalBucketContext(ctx context.Context, tx *bolt.Tx, bucket []byte, cutoffMinute int64, dst map[string]*TopAgg, client bool) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	b := tx.Bucket(bucket)
	if b == nil {
		return 0, nil
	}
	count := 0
	start := []byte(fmt.Sprintf("%012d", cutoffMinute))
	c := b.Cursor()
	for k, v := c.Seek(start); k != nil; k, v = c.Next() {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		parts := strings.SplitN(string(k), "\t", 2)
		if len(parts) != 2 {
			continue
		}
		minute, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || minute < cutoffMinute {
			continue
		}
		name := parts[1]
		total := decodeRollupTotalValue(v)
		a := dst[name]
		if a == nil {
			a = &TopAgg{}
			if client {
				a.Client = name
			} else {
				a.Category = name
			}
			dst[name] = a
		}
		a.Down += total.DownloadBytes
		a.Up += total.UploadBytes
		a.DownP += total.DownloadPackets
		a.UpP += total.UploadPackets
		count++
	}
	return count, nil
}

func aggregateFromRollup(path string, cutoff time.Time, clientFilter string, aggs map[string]*TopAgg) (int, error) {
	return aggregateFromRollupContext(context.Background(), path, cutoff, clientFilter, aggs)
}

func aggregateFromRollupContext(ctx context.Context, path string, cutoff time.Time, clientFilter string, aggs map[string]*TopAgg) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	db, err := bolt.Open(path, 0444, &bolt.Options{ReadOnly: true, Timeout: rollupReadOnlyTimeout})
	if err != nil {
		return 0, err
	}
	defer db.Close()
	cutoffMinute := cutoff.Unix() / 60
	count := 0
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(rollupBucket)
		if b == nil {
			return nil
		}
		start := []byte(fmt.Sprintf("%012d", cutoffMinute))
		c := b.Cursor()
		for k, v := c.Seek(start); k != nil; k, v = c.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}
			var row RollupRow
			if json.Unmarshal(v, &row) != nil {
				continue
			}
			if row.Minute < cutoffMinute {
				continue
			}
			if clientFilter != "" && row.Client != clientFilter {
				continue
			}
			key := row.Client + "\t" + row.Category + "\t" + row.Target + "\t" + row.Proto + "\t" + strconv.Itoa(int(row.Port))
			a := aggs[key]
			if a == nil {
				a = &TopAgg{Client: row.Client, Category: row.Category, Target: row.Target, Proto: row.Proto, Port: row.Port}
				aggs[key] = a
			}
			a.Down += row.DownloadBytes
			a.Up += row.UploadBytes
			a.DownP += row.DownloadPackets
			a.UpP += row.UploadPackets
			count++
		}
		return nil
	})
	return count, err
}
