package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// webTestMux builds the real route table so tests exercise the same
// dispatch (405 wrapper, API 404 fallthrough) as production.
func webTestMux(s *webServer) *http.ServeMux {
	mux := http.NewServeMux()
	s.routes(mux)
	return mux
}

func webTestWriteJSONL(t *testing.T, dir, name string, vals ...any) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, v := range vals {
		if err := enc.Encode(v); err != nil {
			t.Fatal(err)
		}
	}
}

func webTestRollup(t *testing.T, recs []FlowRecord) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rollup.db")
	rollup, err := OpenRollup(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rollup.Close()
	if err := rollup.Add(recs); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestQueryWindowAndLimitClamps(t *testing.T) {
	mk := func(q string) *http.Request { return httptest.NewRequest(http.MethodGet, "/x?"+q, nil) }

	if d := parseSince(mk("since=200000h"), 15*time.Minute); d != maxQueryWindow {
		t.Errorf("parseSince huge = %v, want %v", d, maxQueryWindow)
	}
	if d := parseSince(mk("since=5m"), 15*time.Minute); d != 5*time.Minute {
		t.Errorf("parseSince 5m = %v", d)
	}

	// ?from=1 is the OOM vector: the window must be clamped keeping the to end.
	from, to, ok := parseRange(mk("from=1"))
	if !ok {
		t.Fatal("parseRange from=1 not ok")
	}
	if got := to.Sub(from); got != maxQueryWindow {
		t.Errorf("parseRange window = %v, want %v", got, maxQueryWindow)
	}

	if n := atoiDefault("999999", 50); n != maxLimitParam {
		t.Errorf("atoiDefault huge = %d, want %d", n, maxLimitParam)
	}
	if n := atoiDefault("", 50); n != 50 {
		t.Errorf("atoiDefault empty = %d, want 50", n)
	}
	if n := atoiDefault("-3", 50); n != 50 {
		t.Errorf("atoiDefault negative = %d, want 50", n)
	}
}

func TestUnknownAPIPathReturns404JSON(t *testing.T) {
	srv := &webServer{logDir: t.TempDir(), rollupPath: filepath.Join(t.TempDir(), "missing.db")}
	mux := webTestMux(srv)

	for _, p := range []string{"/api/unknown", "/api/system/extra"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 (body=%s)", p, rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("GET %s content-type = %q, want JSON", p, ct)
		}
	}

	// Non-API unknown paths must still fall back to the SPA.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/clients/diana-iphone", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Errorf("SPA fallback = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestUnknownClientReturns404(t *testing.T) {
	base := time.Now().Add(-2 * time.Minute).Truncate(time.Minute)
	rollupPath := webTestRollup(t, []FlowRecord{
		{TSEnd: base, Client: "alice", RemoteIP: "93.184.216.34", RemotePort: 443, Proto: "tcp", Domain: "example.com", ClientDownloadBytes: 1000},
	})
	logDir := t.TempDir()
	wgConf := filepath.Join(t.TempDir(), "wg0.conf")
	if err := os.WriteFile(wgConf, []byte("[Interface]\n### Client wg-peer\n[Peer]\nAllowedIPs = 10.66.66.9/32\n"), 0644); err != nil {
		t.Fatal(err)
	}
	aliasPath := filepath.Join(t.TempDir(), "clients.yaml")
	if err := os.WriteFile(aliasPath, []byte("people:\n  - display: Diana\n    devices: [diana-iphone]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	aliases, err := loadAliasConfig(aliasPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := &webServer{logDir: logDir, rollupPath: rollupPath, wgConfig: wgConf, aliases: aliases}
	mux := webTestMux(srv)

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}

	if rec := get("/api/clients/ghost?since=15m"); rec.Code != http.StatusNotFound {
		t.Errorf("ghost = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
	}
	// Present in rollup window.
	if rec := get("/api/clients/alice?since=15m"); rec.Code != http.StatusOK {
		t.Errorf("alice = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	// Silent but declared in clients.yaml / wg config: zeros, not 404.
	if rec := get("/api/clients/diana-iphone?since=15m"); rec.Code != http.StatusOK {
		t.Errorf("diana-iphone (roster) = %d, want 200", rec.Code)
	}
	if rec := get("/api/clients/wg-peer?since=15m"); rec.Code != http.StatusOK {
		t.Errorf("wg-peer (wg config) = %d, want 200", rec.Code)
	}
}

func TestAPIMethodNotAllowed(t *testing.T) {
	srv := &webServer{logDir: t.TempDir(), rollupPath: filepath.Join(t.TempDir(), "missing.db")}
	mux := webTestMux(srv)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/clients", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/clients = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != "GET, HEAD" {
		t.Errorf("Allow = %q, want \"GET, HEAD\"", allow)
	}
}

func TestValidateWebAuth(t *testing.T) {
	cases := []struct {
		listen, password string
		allowNoAuth      bool
		wantErr          bool
	}{
		{":8080", "", false, true},
		{"0.0.0.0:8080", "", false, true},
		{"192.168.1.10:8080", "", false, true},
		{":8080", "", true, false},           // explicit escape hatch
		{":8080", "secret", false, false},    // password set
		{"127.0.0.1:8080", "", false, false}, // loopback + tunnel is the blessed setup
		{"[::1]:8080", "", false, false},
		{"localhost:8080", "", false, false},
	}
	for _, tc := range cases {
		err := validateWebAuth(tc.listen, tc.password, tc.allowNoAuth)
		if (err != nil) != tc.wantErr {
			t.Errorf("validateWebAuth(%q, pw=%t, allow=%t) err=%v, wantErr=%t",
				tc.listen, tc.password != "", tc.allowNoAuth, err, tc.wantErr)
		}
	}
}

func TestWebCmdRefusesPasswordlessNonLoopback(t *testing.T) {
	t.Setenv("WGFLOW_WEB_PASSWORD", "")
	err := webCmd([]string{"-listen", "0.0.0.0:0"})
	if err == nil {
		t.Fatal("webCmd started without a password on a non-loopback address")
	}
	if !strings.Contains(err.Error(), "allow-no-auth") {
		t.Errorf("error should mention the escape hatch: %v", err)
	}
}

func TestDBUnavailableReportsDbOkFalseAndUnknownVerdict(t *testing.T) {
	// A garbage file makes bolt.Open fail, which must surface as db_ok=false —
	// never as an all-zero "silent" answer.
	badDB := filepath.Join(t.TempDir(), "rollup.db")
	if err := os.WriteFile(badDB, bytes.Repeat([]byte{0xde, 0xad}, 8192), 0644); err != nil {
		t.Fatal(err)
	}
	srv := &webServer{logDir: t.TempDir(), rollupPath: badDB}
	mux := webTestMux(srv)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/clients?since=15m", nil))
	var clientsResp struct {
		DBOk *bool `json:"db_ok"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &clientsResp); err != nil {
		t.Fatal(err)
	}
	if clientsResp.DBOk == nil || *clientsResp.DBOk {
		t.Errorf("/api/clients db_ok = %v, want false", clientsResp.DBOk)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/snapshot?since=5m&clients=alice", nil))
	var snapResp struct {
		DBOk    *bool `json:"db_ok"`
		Clients []struct {
			Name    string     `json:"name"`
			Verdict apiVerdict `json:"verdict"`
		} `json:"clients"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &snapResp); err != nil {
		t.Fatal(err)
	}
	if snapResp.DBOk == nil || *snapResp.DBOk {
		t.Errorf("/api/snapshot db_ok = %v, want false", snapResp.DBOk)
	}
	if len(snapResp.Clients) != 1 {
		t.Fatalf("snapshot clients = %+v, want the requested alice entry", snapResp.Clients)
	}
	if v := snapResp.Clients[0].Verdict; v.Status != "unknown" || v.Confidence != "low" {
		t.Errorf("verdict = %+v, want unknown/low (not silent!)", v)
	}

	// Client detail must answer 200 (absence is unprovable), flag db_ok=false,
	// and degrade the verdict to unknown.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/clients/alice?since=15m", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("detail with broken DB = %d, want 200", rec.Code)
	}
	var detResp struct {
		DBOk    *bool      `json:"db_ok"`
		Verdict apiVerdict `json:"verdict"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detResp); err != nil {
		t.Fatal(err)
	}
	if detResp.DBOk == nil || *detResp.DBOk {
		t.Errorf("detail db_ok = %v, want false", detResp.DBOk)
	}
	if detResp.Verdict.Status != "unknown" {
		t.Errorf("detail verdict = %+v, want unknown", detResp.Verdict)
	}
}

func TestEncryptedDNSFlag(t *testing.T) {
	now := time.Now()
	base := now.Add(-2 * time.Minute).Truncate(time.Minute)
	rollupPath := webTestRollup(t, []FlowRecord{
		// alice speaks DoT: a flow to port 853, no captured handshake.
		{TSEnd: base, Client: "alice", RemoteIP: "1.1.1.1", RemotePort: 853, Proto: "tcp", ClientDownloadBytes: 900, ClientUploadBytes: 300},
		{TSEnd: base, Client: "alice", RemoteIP: "93.184.216.34", RemotePort: 443, Proto: "tcp", Domain: "example.com", ClientDownloadBytes: 5000},
		// bob speaks DoH: ordinary 443 flows, evidence lives in tls.jsonl.
		{TSEnd: base, Client: "bob", RemoteIP: "104.16.132.229", RemotePort: 443, Proto: "tcp", ClientDownloadBytes: 4000},
		// carol is a plain-DNS client: nothing should be flagged.
		{TSEnd: base, Client: "carol", RemoteIP: "93.184.216.34", RemotePort: 443, Proto: "tcp", Domain: "example.com", ClientDownloadBytes: 3000},
		// dave needs some rollup traffic to appear on the board at all; his
		// encrypted-DNS evidence is the port-853 handshake in tls.jsonl below.
		{TSEnd: base, Client: "dave", RemoteIP: "9.9.9.9", RemotePort: 443, Proto: "tcp", ClientDownloadBytes: 1500},
	})
	logDir := t.TempDir()
	webTestWriteJSONL(t, logDir, "tls.jsonl",
		TLSRecord{TS: now.Add(-3 * time.Minute), Client: "bob", RemoteIP: "104.16.132.229", RemotePort: 443, ServerName: "one.one.one.one"},
		TLSRecord{TS: now.Add(-2 * time.Minute), Client: "carol", RemoteIP: "93.184.216.34", RemotePort: 443, ServerName: "example.com"},
		// dave: DoT handshake on port 853 with no SNI — the port alone is evidence.
		TLSRecord{TS: now.Add(-1 * time.Minute), Client: "dave", RemoteIP: "9.9.9.9", RemotePort: 853, ServerName: ""},
	)
	srv := &webServer{logDir: logDir, rollupPath: rollupPath}
	mux := webTestMux(srv)

	get := func(path string, v any) {
		t.Helper()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d (body=%s)", path, rec.Code, rec.Body.String())
		}
		if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
			t.Fatal(err)
		}
	}

	// Board: the SNI/port evidence from the tls.jsonl walk.
	var clientsResp struct {
		Clients []struct {
			Name         string `json:"name"`
			EncryptedDNS bool   `json:"encrypted_dns"`
		} `json:"clients"`
	}
	get("/api/clients?since=15m", &clientsResp)
	flags := map[string]bool{}
	for _, c := range clientsResp.Clients {
		flags[c.Name] = c.EncryptedDNS
	}
	if !flags["bob"] {
		t.Error("bob (DoH SNI) must be flagged on the board")
	}
	if !flags["dave"] {
		t.Error("dave (handshake on port 853) must be flagged on the board")
	}
	if flags["carol"] {
		t.Error("carol (plain TLS to example.com) must not be flagged")
	}

	// Detail: flow-level port 853 evidence catches alice too.
	var detail struct {
		EncryptedDNS bool `json:"encrypted_dns"`
	}
	get("/api/clients/alice?since=15m", &detail)
	if !detail.EncryptedDNS {
		t.Error("alice detail (flows to port 853 in the window) must be flagged")
	}
	get("/api/clients/carol?since=15m", &detail)
	if detail.EncryptedDNS {
		t.Error("carol detail must not be flagged")
	}

	// Snapshot (the Срез source) carries the same per-client flag.
	var snap struct {
		Clients []struct {
			Name         string `json:"name"`
			EncryptedDNS bool   `json:"encrypted_dns"`
		} `json:"clients"`
	}
	get("/api/snapshot?since=15m", &snap)
	snapFlags := map[string]bool{}
	for _, c := range snap.Clients {
		snapFlags[c.Name] = c.EncryptedDNS
	}
	if !snapFlags["bob"] || snapFlags["carol"] {
		t.Errorf("snapshot flags = %v, want bob=true carol=false", snapFlags)
	}
}

func TestDNSErrorsCountedAfterFilters(t *testing.T) {
	logDir := t.TempDir()
	now := time.Now()
	webTestWriteJSONL(t, logDir, "dns.jsonl",
		DNSRecord{TS: now.Add(-4 * time.Minute), Client: "alice", Query: "fail.alice.example", QType: "A", RCode: 3},
		DNSRecord{TS: now.Add(-3 * time.Minute), Client: "bob", Query: "fail.bob.example", QType: "A", RCode: 3},
		DNSRecord{TS: now.Add(-2 * time.Minute), Client: "alice", Query: "ok.alice.example", QType: "A"},
		DNSRecord{TS: now.Add(-1 * time.Minute), Client: "bob", Query: "ok.bob.example", QType: "A"},
	)
	srv := &webServer{logDir: logDir, rollupPath: filepath.Join(t.TempDir(), "missing.db")}

	rec := httptest.NewRecorder()
	srv.handleDNS(rec, httptest.NewRequest(http.MethodGet, "/api/dns?since=15m&client=alice", nil))
	var got struct {
		Errors  int         `json:"errors"`
		Records []DNSRecord `json:"records"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 2 {
		t.Fatalf("records = %d, want alice's 2", len(got.Records))
	}
	// Bob's error must not inflate alice's badge.
	if got.Errors != 1 {
		t.Errorf("errors = %d, want 1 (after client filter)", got.Errors)
	}
}

func TestDNSRecordsStopAtLimitButErrorsCoverWindow(t *testing.T) {
	logDir := t.TempDir()
	now := time.Now()
	recs := make([]any, 0, 6)
	for i := 6; i >= 1; i-- {
		r := DNSRecord{TS: now.Add(-time.Duration(i) * time.Minute), Client: "alice", Query: fmt.Sprintf("q%d.example", i), QType: "A"}
		if i >= 5 { // the two OLDEST records are errors — past the limit cut
			r.RCode = 2
		}
		recs = append(recs, r)
	}
	webTestWriteJSONL(t, logDir, "dns.jsonl", recs...)
	srv := &webServer{logDir: logDir, rollupPath: filepath.Join(t.TempDir(), "missing.db")}

	rec := httptest.NewRecorder()
	srv.handleDNS(rec, httptest.NewRequest(http.MethodGet, "/api/dns?since=15m&limit=2", nil))
	var got struct {
		Errors  int         `json:"errors"`
		Records []DNSRecord `json:"records"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 2 {
		t.Fatalf("records = %d, want limit 2", len(got.Records))
	}
	if got.Records[0].Query != "q1.example" || got.Records[1].Query != "q2.example" {
		t.Errorf("records must be the newest ones: %+v", got.Records)
	}
	// Both errors are older than the 2 returned records: the badge must still
	// count them even though collection stopped at the limit.
	if got.Errors != 2 {
		t.Errorf("errors = %d, want 2 across the whole window", got.Errors)
	}
}

func TestDayTimelineStartsAtMidnight(t *testing.T) {
	nowMSK := time.Now().In(mskLocation)
	midnight := time.Date(nowMSK.Year(), nowMSK.Month(), nowMSK.Day(), 0, 0, 0, 0, mskLocation)
	today := nowMSK.Truncate(time.Minute)
	yesterday := midnight.Add(-30 * time.Minute) // 23:30 yesterday — inside the old sliding 24h window

	rollupPath := webTestRollup(t, []FlowRecord{
		{TSEnd: today, Client: "alice", RemoteIP: "93.184.216.34", RemotePort: 443, Proto: "tcp", Domain: "example.com", ClientDownloadBytes: 1111},
		{TSEnd: yesterday, Client: "alice", RemoteIP: "93.184.216.34", RemotePort: 443, Proto: "tcp", Domain: "example.com", ClientDownloadBytes: 2222},
	})
	srv := &webServer{rollupPath: rollupPath}
	day := srv.clientDayTimeline("alice")
	if len(day) != 24 {
		t.Fatalf("day len = %d", len(day))
	}

	var sum uint64
	for _, h := range day {
		sum += h.Total
	}
	// Yesterday's 2222 must be gone entirely — under the old sliding window it
	// landed in bucket 23 and read as "today at 23:00".
	if sum != 1111 {
		t.Fatalf("day total = %d, want only today's 1111 (yesterday leaked?)", sum)
	}
	recHour := today.In(mskLocation).Hour()
	if day[recHour].Total != 1111 {
		t.Errorf("bucket[%d] = %d, want 1111", recHour, day[recHour].Total)
	}
	// Hours after "now" must be zero so the frontend can dim them. hourAfter is
	// re-read post-call so an hour rollover mid-test cannot flake this.
	hourAfter := time.Now().In(mskLocation).Hour()
	for h := hourAfter + 1; h < 24; h++ {
		if day[h].Total != 0 {
			t.Errorf("future bucket[%d] = %d, want 0", h, day[h].Total)
		}
	}
}

func TestEachLineReverseCapsRunawayLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "junk.jsonl")
	var buf bytes.Buffer
	buf.WriteString(`{"a":1}` + "\n")
	buf.Write(bytes.Repeat([]byte("x"), 3<<20)) // 3MB with no newline — binary junk stand-in
	buf.WriteString("\n" + `{"b":2}` + "\n")
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	var maxLine int
	seen := map[string]bool{}
	if err := eachLineReverse(path, func(line []byte) bool {
		if len(line) > maxLine {
			maxLine = len(line)
		}
		seen[string(line)] = true
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if !seen[`{"a":1}`] || !seen[`{"b":2}`] {
		t.Error("valid lines around the junk must still be delivered")
	}
	// Without the carry cap the junk arrives as one 3MB "line" (and a junk file
	// the size of the log would arrive whole). Fragments are fine — callers
	// fail to unmarshal them and move on.
	if maxLine >= 2<<20 {
		t.Errorf("max delivered line = %d bytes; carry cap failed", maxLine)
	}
}
