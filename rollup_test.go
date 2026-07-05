package main

import (
	"strconv"
	"testing"
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
