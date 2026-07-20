package main

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestCapPendingRollup(t *testing.T) {
	mk := func(n int) []FlowRecord {
		recs := make([]FlowRecord, n)
		for i := range recs {
			recs[i].RemoteIP = strconv.Itoa(i)
		}
		return recs
	}

	kept, dropped := capPendingRollup(mk(10), 10)
	if dropped != 0 || len(kept) != 10 {
		t.Fatalf("at cap: kept=%d dropped=%d, want 10/0", len(kept), dropped)
	}

	kept, dropped = capPendingRollup(mk(15), 10)
	if dropped != 5 || len(kept) != 10 {
		t.Fatalf("over cap: kept=%d dropped=%d, want 10/5", len(kept), dropped)
	}
	// The oldest records go first; the newest must survive.
	if kept[0].RemoteIP != "5" || kept[9].RemoteIP != "14" {
		t.Fatalf("kept window = %s..%s, want 5..14", kept[0].RemoteIP, kept[9].RemoteIP)
	}

	kept, dropped = capPendingRollup(nil, 10)
	if dropped != 0 || kept != nil {
		t.Fatalf("nil queue: kept=%v dropped=%d", kept, dropped)
	}
}

func TestPruneRollup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollup.db")
	rollup, err := OpenRollup(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rollup.Close()

	old := time.Now().Add(-40 * 24 * time.Hour).Truncate(time.Minute)
	recent := time.Now().Add(-1 * time.Hour).Truncate(time.Minute)
	recs := []FlowRecord{
		{TSEnd: old, Client: "alice", RemoteIP: "87.250.250.242", RemotePort: 443, Proto: "tcp", Domain: "api.music.yandex.net", ClientDownloadBytes: 1000},
		{TSEnd: recent, Client: "alice", RemoteIP: "87.250.250.242", RemotePort: 443, Proto: "tcp", Domain: "api.music.yandex.net", ClientDownloadBytes: 2000},
	}
	if err := rollup.Add(recs); err != nil {
		t.Fatal(err)
	}

	// One old minute populates one key in each of the 4 buckets -> prune deletes 4.
	n, err := pruneRollup(path, time.Now().Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("pruned %d keys, want 4 (one old minute across all 4 buckets)", n)
	}

	// The recent flow must survive intact.
	byClient, _, _, err := aggregateReportTotalsFromRollup(path, time.Now().Add(-90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if byClient["alice"].Down != 2000 {
		t.Fatalf("download after prune = %d, want 2000 (old gone, recent kept)", byClient["alice"].Down)
	}

	// Idempotent: nothing left older than the cutoff.
	if n2, err := pruneRollup(path, time.Now().Add(-30*24*time.Hour)); err != nil || n2 != 0 {
		t.Fatalf("second prune = %d (err %v), want 0", n2, err)
	}
}

func TestPruneRollupTiersKeepsCompactHistoryLonger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollup.db")
	rollup, err := OpenRollup(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rollup.Close()

	now := time.Now().Truncate(time.Minute)
	recs := []FlowRecord{
		{TSEnd: now.Add(-40 * 24 * time.Hour), Client: "alice", RemoteIP: "1.1.1.1", RemotePort: 443, Proto: "tcp", ClientDownloadBytes: 1000},
		{TSEnd: now.Add(-10 * 24 * time.Hour), Client: "alice", RemoteIP: "8.8.8.8", RemotePort: 443, Proto: "tcp", ClientDownloadBytes: 2000},
		{TSEnd: now.Add(-1 * time.Hour), Client: "alice", RemoteIP: "9.9.9.9", RemotePort: 443, Proto: "tcp", ClientDownloadBytes: 4000},
	}
	if err := rollup.Add(recs); err != nil {
		t.Fatal(err)
	}

	detailDeleted, summaryDeleted, err := pruneRollupTiers(
		path,
		now.Add(-31*24*time.Hour),
		now.Add(-7*24*time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	if detailDeleted != 2 {
		t.Fatalf("detail deleted=%d, want 2", detailDeleted)
	}
	if summaryDeleted != 3 {
		t.Fatalf("summary deleted=%d, want 3 (old client/category/client-category keys)", summaryDeleted)
	}

	byClient, _, _, err := aggregateReportTotalsFromRollup(path, now.Add(-90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got := byClient["alice"].Down; got != 6000 {
		t.Fatalf("compact summary download=%d, want 6000 (10d + recent)", got)
	}

	details := map[string]*TopAgg{}
	if _, err := aggregateFromRollup(path, now.Add(-90*24*time.Hour), "alice", details); err != nil {
		t.Fatal(err)
	}
	var detailDown uint64
	for _, a := range details {
		detailDown += a.Down
	}
	if detailDown != 4000 {
		t.Fatalf("per-target detail download=%d, want only recent 4000", detailDown)
	}
}

func TestPruneRollupTiersReleasesLockBetweenBatches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollup.db")
	rollup, err := OpenRollup(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rollup.Close()

	now := time.Now().Truncate(time.Minute)
	old := make([]FlowRecord, 5)
	for i := range old {
		old[i] = FlowRecord{
			TSEnd:               now.Add(-40*24*time.Hour + time.Duration(i)*time.Minute),
			Client:              "alice",
			RemoteIP:            "1.1.1.1",
			RemotePort:          443,
			Proto:               "tcp",
			ClientDownloadBytes: 100,
		}
	}
	if err := rollup.Add(old); err != nil {
		t.Fatal(err)
	}

	var batches int
	var hookErr error
	injected := false
	detailDeleted, summaryDeleted, err := pruneRollupTiersWithOptions(
		path,
		now.Add(-31*24*time.Hour),
		now.Add(-7*24*time.Hour),
		rollupPruneOptions{
			batchKeys: 1,
			afterBatch: func() {
				batches++
				if hookErr != nil {
					return
				}
				db, err := openRollupReadOnly(path)
				if err != nil {
					hookErr = err
					return
				}
				if err := db.Close(); err != nil {
					hookErr = err
					return
				}
				if !injected {
					injected = true
					hookErr = rollup.Add([]FlowRecord{{
						TSEnd:               now,
						Client:              "alice",
						RemoteIP:            "9.9.9.9",
						RemotePort:          443,
						Proto:               "tcp",
						ClientDownloadBytes: 900,
					}})
				}
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if hookErr != nil {
		t.Fatalf("database unavailable between prune batches: %v", hookErr)
	}
	if batches < 2 {
		t.Fatalf("prune batches=%d, want multiple batches", batches)
	}
	if detailDeleted != 5 || summaryDeleted != 15 {
		t.Fatalf("deleted detail/summary=%d/%d, want 5/15", detailDeleted, summaryDeleted)
	}

	byClient, _, _, err := aggregateReportTotalsFromRollup(path, now.Add(-90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got := byClient["alice"].Down; got != 900 {
		t.Fatalf("download after batched prune=%d, want injected recent 900", got)
	}
}

func TestRollupAggregatesHonorCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path := filepath.Join(t.TempDir(), "rollup.db")
	cutoff := time.Now().Add(-time.Hour)

	if _, err := aggregateFromRollupContext(ctx, path, cutoff, "", map[string]*TopAgg{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("aggregateFromRollupContext error=%v, want context.Canceled", err)
	}
	if _, _, _, err := aggregateReportTotalsFromRollupContext(ctx, path, cutoff); !errors.Is(err, context.Canceled) {
		t.Fatalf("aggregateReportTotalsFromRollupContext error=%v, want context.Canceled", err)
	}
}
