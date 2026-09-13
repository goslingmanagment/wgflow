package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseRetention(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"30d", 30 * 24 * time.Hour, false},
		{"12w", 12 * 7 * 24 * time.Hour, false},
		{"1.5d", 36 * time.Hour, false},
		{"720h", 720 * time.Hour, false},
		{"5m", 5 * time.Minute, false},
		{"0", 0, false},
		// Negative values parse; callers treat <= 0 as "keep forever" or reject.
		{"-2d", -48 * time.Hour, false},
		{"", 0, true},
		{"abc", 0, true},
		{"10x", 0, true},
		{"d", 0, true},
		{" 30d ", 30 * 24 * time.Hour, false},
	}
	for _, tc := range cases {
		got, err := parseRetention(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseRetention(%q) = %v, want error", tc.in, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("parseRetention(%q) = (%v, %v), want %v", tc.in, got, err, tc.want)
		}
	}
}

func TestClientMapLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg0.conf")
	conf := `[Interface]
Address = 10.66.66.1/24
PrivateKey = xxx

### Client alice
[Peer]
PublicKey = yyy
AllowedIPs = 10.66.66.2/32, fd42:42:42::2/128

### Client bob
[Peer]
PublicKey = zzz
AllowedIPs = 10.66.66.3

[Peer]
# no ### Client header -> must be ignored
AllowedIPs = 10.66.66.99/32
`
	if err := os.WriteFile(path, []byte(conf), 0644); err != nil {
		t.Fatal(err)
	}
	c := &ClientMap{}
	if err := c.Load(path, []string{"10.66.66.0/24"}); err != nil {
		t.Fatal(err)
	}
	c.mu.RLock()
	byIP := c.byIP
	c.mu.RUnlock()
	if byIP["10.66.66.2"] != "alice" || byIP["fd42:42:42::2"] != "alice" {
		t.Fatalf("alice IPs = %v", byIP)
	}
	if byIP["10.66.66.3"] != "bob" {
		t.Fatalf("bare-IP AllowedIPs (no CIDR) must map, got %v", byIP)
	}
	// The orphan peer keeps the previous "### Client" name — that is the
	// documented parsing model (name applies until the next header).
	if got := byIP["10.66.66.99"]; got != "bob" {
		t.Fatalf("orphan peer = %q, want bob (name carries over)", got)
	}
	if c.Count() != 4 {
		t.Fatalf("Count = %d, want 4", c.Count())
	}

	if err := c.Load(path, []string{"not-a-cidr"}); err == nil {
		t.Fatal("invalid vpn cidr must be an error")
	}
}

func TestClientMapLoadWGEasyComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg0.conf")
	conf := `[Interface]
Address = 10.8.0.1/24

# Client: diana-iphone (3)
[Peer]
PublicKey = aaa
AllowedIPs = 10.8.0.4/32, fdcc:ad94:bacf:61a4::cafe:4/128

# Client: Diana MacBook (42)
[Peer]
PublicKey = bbb
AllowedIPs = 10.8.0.5/32
`
	if err := os.WriteFile(path, []byte(conf), 0644); err != nil {
		t.Fatal(err)
	}
	c := &ClientMap{}
	if err := c.Load(path, []string{"10.8.0.0/24", "fdcc:ad94:bacf:61a4::/64"}); err != nil {
		t.Fatal(err)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if got := c.byIP["10.8.0.4"]; got != "diana-iphone" {
		t.Fatalf("wg-easy iphone name = %q", got)
	}
	if got := c.byIP["fdcc:ad94:bacf:61a4::cafe:4"]; got != "diana-iphone" {
		t.Fatalf("wg-easy iphone IPv6 name = %q", got)
	}
	if got := c.byIP["10.8.0.5"]; got != "Diana MacBook" {
		t.Fatalf("wg-easy MacBook name = %q", got)
	}
}

func TestParseExtraCaptureSource(t *testing.T) {
	raw := "name=wg-easy,iface=wg0,wg-config=/opt/wg-easy/wg0.conf,cidrs=10.8.0.0/24|fdcc:ad94:bacf:61a4::/64,netns=/proc/123/ns/net"
	got, err := parseExtraCaptureSource(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "wg-easy" || got.Iface != "wg0" || got.WGConfigPath != "/opt/wg-easy/wg0.conf" || got.NetNSPath != "/proc/123/ns/net" {
		t.Fatalf("parsed source = %+v", got)
	}
	if len(got.VPNCIDRs) != 2 || got.VPNCIDRs[0] != "10.8.0.0/24" || got.VPNCIDRs[1] != "fdcc:ad94:bacf:61a4::/64" {
		t.Fatalf("parsed cidrs = %v", got.VPNCIDRs)
	}

	bad := []string{
		"",
		"name=wg-easy,iface=wg0,wg-config=/x",
		"name=wg-easy,iface=wg0,wg-config=/x,cidrs=bad",
		"name=wg-easy,iface=wg0,wg-config=/x,cidrs=10.8.0.0/24,nope=x",
		"name=wg-easy,name=again,iface=wg0,wg-config=/x,cidrs=10.8.0.0/24",
	}
	for _, raw := range bad {
		if _, err := parseExtraCaptureSource(raw); err == nil {
			t.Errorf("parseExtraCaptureSource(%q) succeeded, want error", raw)
		}
	}
}

func writeFlowLines(t *testing.T, path string, recs []FlowRecord, tail string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, rec := range recs {
		if err := enc.Encode(rec); err != nil {
			t.Fatal(err)
		}
	}
	if tail != "" {
		if _, err := f.WriteString(tail); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReadRecentFlowRecordsAcrossBlocks(t *testing.T) {
	// Enough records to span several 256 KiB read blocks, so lines are torn
	// at block boundaries and reassembled via the carry buffer.
	path := filepath.Join(t.TempDir(), "flows.jsonl")
	base := time.Now().Add(-time.Hour).Truncate(time.Second)
	var recs []FlowRecord
	for i := 0; i < 4000; i++ {
		recs = append(recs, FlowRecord{
			TSEnd:    base.Add(time.Duration(i) * time.Second),
			Client:   "alice",
			RemoteIP: "93.184.216.34",
			Domain:   strings.Repeat("x", 150) + ".example.com",
		})
	}
	writeFlowLines(t, path, recs, "")
	if st, _ := os.Stat(path); st.Size() < 3*256*1024 {
		t.Fatalf("test file too small to cross blocks: %d bytes", st.Size())
	}
	var got int
	if err := readRecentFlowRecords(path, base.Add(-time.Minute), func(rec FlowRecord) {
		got++
	}); err != nil {
		t.Fatal(err)
	}
	if got != 4000 {
		t.Fatalf("records = %d, want 4000 (lines torn at block boundaries must survive)", got)
	}
}

func TestReadRecentFlowRecordsLineLongerThanBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flows.jsonl")
	base := time.Now().Add(-time.Hour).Truncate(time.Second)
	huge := strings.Repeat("a", 300*1024) + ".example.com" // > one 256 KiB block
	recs := []FlowRecord{
		{TSEnd: base, Client: "alice", Domain: "first.example.com"},
		{TSEnd: base.Add(time.Second), Client: "alice", Domain: huge},
		{TSEnd: base.Add(2 * time.Second), Client: "alice", Domain: "last.example.com"},
	}
	writeFlowLines(t, path, recs, "")
	var domains []string
	if err := readRecentFlowRecords(path, base.Add(-time.Minute), func(rec FlowRecord) {
		domains = append(domains, rec.Domain)
	}); err != nil {
		t.Fatal(err)
	}
	if len(domains) != 3 {
		t.Fatalf("records = %d, want 3", len(domains))
	}
	// Records come back newest-first.
	if domains[0] != "last.example.com" || domains[1] != huge || domains[2] != "first.example.com" {
		t.Fatalf("order/content wrong: [%d chars] %q %q", len(domains[1]), domains[0], domains[2])
	}
}

func TestReadRecentFlowRecordsTornLastLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flows.jsonl")
	base := time.Now().Add(-time.Hour).Truncate(time.Second)
	recs := []FlowRecord{
		{TSEnd: base, Client: "alice", Domain: "ok.example.com"},
	}
	// Simulate a crash mid-write: the final line is truncated JSON without a
	// trailing newline.
	writeFlowLines(t, path, recs, `{"ts_end":"2026-07-05T10:`)
	var got []string
	if err := readRecentFlowRecords(path, base.Add(-time.Minute), func(rec FlowRecord) {
		got = append(got, rec.Domain)
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "ok.example.com" {
		t.Fatalf("records = %v, want just the intact line", got)
	}
}

func TestReadRecentFlowRecordsCutoffStopsEarly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flows.jsonl")
	base := time.Now().Add(-time.Hour).Truncate(time.Second)
	recs := []FlowRecord{
		{TSEnd: base.Add(-30 * time.Minute), Client: "alice", Domain: "old.example.com"},
		{TSEnd: base.Add(-20 * time.Minute), Client: "alice", Domain: "older.example.com"},
		{TSEnd: base, Client: "alice", Domain: "new1.example.com"},
		{TSEnd: base.Add(time.Second), Client: "alice", Domain: "new2.example.com"},
	}
	writeFlowLines(t, path, recs, "")
	var got []string
	if err := readRecentFlowRecords(path, base.Add(-time.Minute), func(rec FlowRecord) {
		got = append(got, rec.Domain)
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "new2.example.com" || got[1] != "new1.example.com" {
		t.Fatalf("records = %v, want only the two records after the cutoff", got)
	}
}

func TestReadRecentFlowRecordsMissingFile(t *testing.T) {
	err := readRecentFlowRecords(filepath.Join(t.TempDir(), "nope.jsonl"), time.Now(), func(FlowRecord) {})
	if err == nil {
		t.Fatal("missing file must return an error")
	}
}
