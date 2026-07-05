package main

import (
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

// pruneRollup deletes every minute bucket older than cutoff across all four
// rollup buckets. The three minute-prefixed buckets are key-sorted by minute so
// we stop at the cutoff; the client-category bucket (client\tminute\tcat) is not,
// so it is full-scanned. bbolt reuses the freed pages, so the file stops growing
// (it does not shrink on disk without a separate compaction).
func pruneRollup(path string, cutoff time.Time) (int, error) {
	cutoffMinute := cutoff.Unix() / 60
	db, err := bolt.Open(path, 0644, &bolt.Options{Timeout: 30 * time.Second})
	if err != nil {
		return 0, err
	}
	defer db.Close()
	deleted := 0
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{rollupBucket, rollupClientBucket, rollupCategoryBucket} {
			b := tx.Bucket(name)
			if b == nil {
				continue
			}
			var del [][]byte
			c := b.Cursor()
			for k, _ := c.First(); k != nil; k, _ = c.Next() {
				m := minutePrefix(k)
				if m < 0 {
					continue
				}
				if m >= cutoffMinute {
					break // keys are sorted by minute
				}
				del = append(del, append([]byte(nil), k...))
			}
			for _, k := range del {
				if err := b.Delete(k); err != nil {
					return err
				}
				deleted++
			}
		}
		if b := tx.Bucket(rollupClientCategoryBucket); b != nil {
			var del [][]byte
			c := b.Cursor()
			for k, _ := c.First(); k != nil; k, _ = c.Next() {
				parts := strings.SplitN(string(k), "\t", 3)
				if len(parts) != 3 {
					continue
				}
				if m, err := strconv.ParseInt(parts[1], 10, 64); err == nil && m < cutoffMinute {
					del = append(del, append([]byte(nil), k...))
				}
			}
			for _, k := range del {
				if err := b.Delete(k); err != nil {
					return err
				}
				deleted++
			}
		}
		return nil
	})
	return deleted, err
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
	byClient := map[string]*TopAgg{}
	byCategory := map[string]*TopAgg{}
	db, err := bolt.Open(path, 0444, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		return byClient, byCategory, 0, err
	}
	defer db.Close()
	cutoffMinute := cutoff.Unix() / 60
	count := 0
	err = db.View(func(tx *bolt.Tx) error {
		count += readRollupTotalBucket(tx, rollupClientBucket, cutoffMinute, byClient, true)
		count += readRollupTotalBucket(tx, rollupCategoryBucket, cutoffMinute, byCategory, false)
		return nil
	})
	return byClient, byCategory, count, err
}

func readRollupTotalBucket(tx *bolt.Tx, bucket []byte, cutoffMinute int64, dst map[string]*TopAgg, client bool) int {
	b := tx.Bucket(bucket)
	if b == nil {
		return 0
	}
	count := 0
	start := []byte(fmt.Sprintf("%012d", cutoffMinute))
	c := b.Cursor()
	for k, v := c.Seek(start); k != nil; k, v = c.Next() {
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
	return count
}

func aggregateFromRollup(path string, cutoff time.Time, clientFilter string, aggs map[string]*TopAgg) (int, error) {
	db, err := bolt.Open(path, 0444, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
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
