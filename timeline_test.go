package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// timelineTestServer wires a rollup fixture and a log directory the way the
// production web server sees them. No stats.json is written, so
// flushGeneration() returns 0 and both caches stay disabled — each test
// observes its own scan.
func timelineTestServer(t *testing.T, recs []FlowRecord) *webServer {
	t.Helper()
	return &webServer{logDir: t.TempDir(), rollupPath: webTestRollup(t, recs)}
}

func timelineGet(t *testing.T, srv *webServer, client, query string) apiTimeline {
	t.Helper()
	rec := httptest.NewRecorder()
	webTestMux(srv).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/clients/"+client+"/timeline"+query, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET timeline%s = %d (%s)", query, rec.Code, rec.Body.String())
	}
	var out apiTimeline
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode timeline: %v (body=%s)", err, rec.Body.String())
	}
	return out
}

func timelineMinuteAt(t *testing.T, tl apiTimeline, at time.Time) apiTimelineMinute {
	t.Helper()
	for _, m := range tl.Minutes {
		if m.T == at.Unix() {
			return m
		}
	}
	t.Fatalf("no timeline minute at %d; got %+v", at.Unix(), tl.Minutes)
	return apiTimelineMinute{}
}

func timelineServiceIn(services []apiTimelineService, name string) (apiTimelineService, bool) {
	for _, s := range services {
		if s.Service == name {
			return s, true
		}
	}
	return apiTimelineService{}, false
}

func TestTimelineSplitsBurstsOnSilence(t *testing.T) {
	base := time.Now().Truncate(time.Minute).Add(-20 * time.Minute)
	mk := func(offset time.Duration, down, up uint64) FlowRecord {
		return FlowRecord{
			TSEnd: base.Add(offset), Client: "alice", ClientIP: "10.0.0.2",
			RemoteIP: "93.184.216.34", RemotePort: 443, Proto: "tcp", Domain: "picsart.com",
			ClientDownloadBytes: down, ClientUploadBytes: up,
		}
	}
	srv := timelineTestServer(t, []FlowRecord{
		mk(0, 500_000, 100_000),
		mk(time.Minute, 400_000, 0),
		// Nine silent minutes: far wider than the default 5-minute gap.
		mk(10*time.Minute, 300_000, 50_000),
		mk(11*time.Minute, 200_000, 0),
	})

	tl := timelineGet(t, srv, "alice", "?since=30m")
	if !tl.DBOK {
		t.Fatalf("db_ok = false, note=%q", tl.Note)
	}
	if tl.GapSeconds != int(timelineSessionGap/time.Second) {
		t.Errorf("gap_seconds = %d, want %d", tl.GapSeconds, int(timelineSessionGap/time.Second))
	}
	if len(tl.Minutes) != 4 {
		t.Fatalf("minutes = %d, want 4 (only minutes with bytes): %+v", len(tl.Minutes), tl.Minutes)
	}
	for i := 1; i < len(tl.Minutes); i++ {
		if tl.Minutes[i].T <= tl.Minutes[i-1].T {
			t.Fatalf("minutes are not ascending: %+v", tl.Minutes)
		}
	}
	if len(tl.Sessions) != 2 {
		t.Fatalf("sessions = %d, want 2: %+v", len(tl.Sessions), tl.Sessions)
	}

	first, second := tl.Sessions[0], tl.Sessions[1]
	if first.From != base.Unix() || first.To != base.Add(2*time.Minute).Unix() {
		t.Errorf("session 1 = [%d, %d), want [%d, %d)", first.From, first.To, base.Unix(), base.Add(2*time.Minute).Unix())
	}
	if first.Minutes != 2 || first.Bytes != 1_000_000 || first.Down != 900_000 || first.Up != 100_000 {
		t.Errorf("session 1 totals = %+v, want 2 minutes / 1000000 bytes / 900000 down / 100000 up", first)
	}
	if first.Direction != "download" {
		t.Errorf("session 1 direction = %q, want download", first.Direction)
	}
	if second.From != base.Add(10*time.Minute).Unix() || second.To != base.Add(12*time.Minute).Unix() {
		t.Errorf("session 2 = [%d, %d), want [%d, %d)", second.From, second.To,
			base.Add(10*time.Minute).Unix(), base.Add(12*time.Minute).Unix())
	}
	if second.Minutes != 2 || second.Bytes != 550_000 || second.Down != 500_000 || second.Up != 50_000 {
		t.Errorf("session 2 totals = %+v, want 2 minutes / 550000 bytes / 500000 down / 50000 up", second)
	}
	if first.Leader == nil || first.Leader.Service != "picsart.com" {
		t.Errorf("session 1 leader = %+v, want picsart.com", first.Leader)
	}
}

func TestTimelineNewOnlyForServicesUnseenBeforeWindow(t *testing.T) {
	base := time.Now().Truncate(time.Minute).Add(-20 * time.Minute)
	srv := timelineTestServer(t, []FlowRecord{
		{TSEnd: base.Add(2 * time.Minute), Client: "alice", RemoteIP: "93.184.216.34", RemotePort: 443,
			Proto: "tcp", Domain: "cdn.oldsite.com", ClientDownloadBytes: 500_000},
		{TSEnd: base.Add(3 * time.Minute), Client: "alice", RemoteIP: "93.184.216.35", RemotePort: 443,
			Proto: "tcp", Domain: "www.newsite.com", ClientDownloadBytes: 500_000},
	})
	// Ascending order: the reverse scan reads newest-first and stops at the cutoff.
	webTestWriteJSONL(t, srv.logDir, "tls.jsonl",
		TLSRecord{TS: base.Add(-15 * time.Minute), Client: "alice", RemoteIP: "93.184.216.34", RemotePort: 443, ServerName: "cdn.oldsite.com", Protocol: "tls"},
		TLSRecord{TS: base.Add(2*time.Minute + 10*time.Second), Client: "alice", RemoteIP: "93.184.216.34", RemotePort: 443, ServerName: "cdn.oldsite.com", Protocol: "tls"},
		TLSRecord{TS: base.Add(3*time.Minute + 5*time.Second), Client: "alice", RemoteIP: "93.184.216.35", RemotePort: 443, ServerName: "www.newsite.com", Protocol: "tls"},
	)

	tl := timelineGet(t, srv, "alice", "?since=30m")
	old, ok := timelineServiceIn(timelineMinuteAt(t, tl, base.Add(2*time.Minute)).Services, "oldsite.com")
	if !ok {
		t.Fatalf("oldsite.com missing from minute %d: %+v", base.Add(2*time.Minute).Unix(), tl.Minutes)
	}
	if old.New {
		t.Error("oldsite.com is new, but it was already seen before the window")
	}
	fresh, ok := timelineServiceIn(timelineMinuteAt(t, tl, base.Add(3*time.Minute)).Services, "newsite.com")
	if !ok {
		t.Fatalf("newsite.com missing from minute %d: %+v", base.Add(3*time.Minute).Unix(), tl.Minutes)
	}
	if !fresh.New {
		t.Error("newsite.com is not new, but its first trace is inside the window")
	}

	// The session that covers both minutes must report only the fresh one.
	var found bool
	for _, s := range tl.Sessions {
		if s.From <= base.Add(3*time.Minute).Unix() && s.To > base.Add(3*time.Minute).Unix() {
			found = true
			if len(s.NewServices) != 1 || s.NewServices[0] != "newsite.com" {
				t.Errorf("session new_services = %v, want [newsite.com]", s.NewServices)
			}
		}
	}
	if !found {
		t.Errorf("no session covers the fresh minute: %+v", tl.Sessions)
	}
}

func TestTimelineLeaderSkipsInfraAndSDKOnlySessions(t *testing.T) {
	base := time.Now().Truncate(time.Minute).Add(-20 * time.Minute)
	srv := timelineTestServer(t, []FlowRecord{
		// The biggest row is a Cloudflare-category edge: infrastructure never leads.
		{TSEnd: base, Client: "alice", RemoteIP: "104.16.4.4", RemotePort: 443, Proto: "tcp",
			Domain: "cdnjs.cloudflare.com", ClientDownloadBytes: 900_000},
		{TSEnd: base, Client: "alice", RemoteIP: "93.184.216.34", RemotePort: 443, Proto: "tcp",
			Domain: "picsart.com", ClientDownloadBytes: 400_000},
		{TSEnd: base, Client: "alice", RemoteIP: "93.184.216.36", RemotePort: 443, Proto: "tcp",
			Domain: "ms.applovin.com", ClientDownloadBytes: 30_000},
		// Ten minutes later: ad SDKs only, kept alive by a first-seen service.
		{TSEnd: base.Add(10 * time.Minute), Client: "alice", RemoteIP: "93.184.216.37", RemotePort: 443,
			Proto: "tcp", Domain: "ads.vungle.com", ClientDownloadBytes: 30_000},
		{TSEnd: base.Add(10 * time.Minute), Client: "alice", RemoteIP: "93.184.216.36", RemotePort: 443,
			Proto: "tcp", Domain: "ms.applovin.com", ClientDownloadBytes: 20_000},
	})
	webTestWriteJSONL(t, srv.logDir, "tls.jsonl",
		TLSRecord{TS: base.Add(5 * time.Second), Client: "alice", RemoteIP: "93.184.216.36", RemotePort: 443, ServerName: "ms.applovin.com", Protocol: "tls"},
		TLSRecord{TS: base.Add(10*time.Minute + 5*time.Second), Client: "alice", RemoteIP: "93.184.216.37", RemotePort: 443, ServerName: "ads.vungle.com", Protocol: "tls"},
	)

	tl := timelineGet(t, srv, "alice", "?since=30m")
	if len(tl.Sessions) != 2 {
		t.Fatalf("sessions = %d, want 2: %+v", len(tl.Sessions), tl.Sessions)
	}
	lead, ads := tl.Sessions[0], tl.Sessions[1]
	if lead.Leader == nil || lead.Leader.Service != "picsart.com" {
		t.Fatalf("session 1 leader = %+v, want picsart.com (cloudflare is infra)", lead.Leader)
	}
	if len(lead.SDK) != 1 || lead.SDK[0] != "AppLovin" {
		t.Errorf("session 1 sdk = %v, want [AppLovin]", lead.SDK)
	}
	if ads.Leader != nil {
		t.Errorf("ad-SDK-only session leader = %+v, want null", ads.Leader)
	}
	if len(ads.SDK) != 2 || ads.SDK[0] != "Vungle" || ads.SDK[1] != "AppLovin" {
		t.Errorf("ad session sdk = %v, want [Vungle AppLovin]", ads.SDK)
	}
}

func TestTimelineBareIPsUseAttributionThenOrg(t *testing.T) {
	base := time.Now().Truncate(time.Minute).Add(-10 * time.Minute)
	srv := timelineTestServer(t, []FlowRecord{
		// Attributed by a handshake to the same IP for the same client.
		{TSEnd: base, Client: "alice", RemoteIP: "104.16.4.4", RemotePort: 443, Proto: "udp",
			ClientDownloadBytes: 400_000},
		// No handshake ever mentioned this IP: only the network owner is known.
		{TSEnd: base, Client: "alice", RemoteIP: "142.250.1.1", RemotePort: 443, Proto: "udp",
			ClientDownloadBytes: 300_000},
	})
	webTestWriteJSONL(t, srv.logDir, "tls.jsonl",
		TLSRecord{TS: base.Add(-time.Minute), Client: "alice", RemoteIP: "104.16.4.4", RemotePort: 443,
			ServerName: "upload.picsart.com", Protocol: "quic"},
	)

	tl := timelineGet(t, srv, "alice", "?since=30m")
	minute := timelineMinuteAt(t, tl, base)
	named, ok := timelineServiceIn(minute.Services, "picsart.com")
	if !ok {
		t.Fatalf("attributed bare IP did not become picsart.com: %+v", minute.Services)
	}
	if named.Unnamed {
		t.Error("attributed bare IP is flagged unnamed")
	}
	if named.Bytes != 400_000 {
		t.Errorf("attributed bytes = %d, want 400000", named.Bytes)
	}
	org, ok := timelineServiceIn(minute.Services, "Google")
	if !ok {
		t.Fatalf("unattributed bare IP did not fall back to its org: %+v", minute.Services)
	}
	if !org.Unnamed {
		t.Error("org-labeled bare IP must be flagged unnamed")
	}
	if org.Role != "" || org.Bytes != 300_000 {
		t.Errorf("org row = %+v, want role \"\" and 300000 bytes", org)
	}
}

func TestTimelineWiderThanCapReturnsNullsWithNote(t *testing.T) {
	base := time.Now().Truncate(time.Minute).Add(-20 * time.Minute)
	srv := timelineTestServer(t, []FlowRecord{{
		TSEnd: base, Client: "alice", RemoteIP: "93.184.216.34", RemotePort: 443,
		Proto: "tcp", Domain: "picsart.com", ClientDownloadBytes: 500_000,
	}})

	rec := httptest.NewRecorder()
	webTestMux(srv).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/clients/alice/timeline?since=7h", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("over-cap window = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var raw struct {
		Minutes  json.RawMessage `json:"minutes"`
		Sessions json.RawMessage `json:"sessions"`
		Note     string          `json:"note"`
		DBOK     bool            `json:"db_ok"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw.Minutes) != "null" || string(raw.Sessions) != "null" {
		t.Errorf("over-cap minutes/sessions = %s / %s, want null / null", raw.Minutes, raw.Sessions)
	}
	if raw.Note == "" {
		t.Error("over-cap response has no note explaining the empty timeline")
	}
	if !raw.DBOK {
		t.Error("db_ok = false although the rollup opened fine")
	}

	// Just inside the cap still renders.
	tl := timelineGet(t, srv, "alice", "?since=5h")
	if tl.Note != "" || len(tl.Minutes) != 1 {
		t.Errorf("in-cap window = %d minutes, note=%q, want 1 minute and no note", len(tl.Minutes), tl.Note)
	}
}

func TestTimelineGapIsClampedAndApplied(t *testing.T) {
	base := time.Now().Truncate(time.Minute).Add(-20 * time.Minute)
	mk := func(offset time.Duration) FlowRecord {
		return FlowRecord{
			TSEnd: base.Add(offset), Client: "alice", RemoteIP: "93.184.216.34", RemotePort: 443,
			Proto: "tcp", Domain: "picsart.com", ClientDownloadBytes: 500_000,
		}
	}
	srv := timelineTestServer(t, []FlowRecord{mk(0), mk(time.Minute), mk(10 * time.Minute), mk(11 * time.Minute)})

	cases := []struct {
		query        string
		wantGap      int
		wantSessions int
	}{
		{"?since=30m&gap=5", 60, 4},      // floor: 60s between minute starts means no clustering at all
		{"?since=30m&gap=99999", 900, 1}, // above the ceiling: clamped to 900s
		{"?since=30m&gap=abc", 300, 2},   // unparsable: the default
		{"?since=30m&gap=600", 600, 1},   // in range: the 9-minute silence no longer splits
		{"?since=30m&gap=120", 120, 2},   // in range: it still does
	}
	for _, tc := range cases {
		tl := timelineGet(t, srv, "alice", tc.query)
		if tl.GapSeconds != tc.wantGap {
			t.Errorf("%s gap_seconds = %d, want %d", tc.query, tl.GapSeconds, tc.wantGap)
		}
		if len(tl.Sessions) != tc.wantSessions {
			t.Errorf("%s sessions = %d, want %d: %+v", tc.query, len(tl.Sessions), tc.wantSessions, tl.Sessions)
		}
	}
}

func TestTimelineReportsDBOutageInsteadOfSilence(t *testing.T) {
	badDB := filepath.Join(t.TempDir(), "rollup.db")
	if err := os.WriteFile(badDB, bytes.Repeat([]byte{0xde, 0xad}, 8192), 0644); err != nil {
		t.Fatal(err)
	}
	srv := &webServer{logDir: t.TempDir(), rollupPath: badDB}

	rec := httptest.NewRecorder()
	webTestMux(srv).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/clients/alice/timeline?since=30m", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("unreadable rollup = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var raw struct {
		DBOK     *bool           `json:"db_ok"`
		Note     string          `json:"note"`
		Minutes  json.RawMessage `json:"minutes"`
		Sessions json.RawMessage `json:"sessions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if raw.DBOK == nil || *raw.DBOK {
		t.Errorf("db_ok = %v, want false", raw.DBOK)
	}
	if raw.Note == "" {
		t.Error("an unreadable rollup must not read as a quiet client: no note")
	}
	if string(raw.Minutes) != "[]" || string(raw.Sessions) != "[]" {
		t.Errorf("minutes/sessions = %s / %s, want [] / [] (the window was in range)", raw.Minutes, raw.Sessions)
	}
}

// A handshake at :02:40 is flushed into the :03 rollup row (30 s cadence,
// bucketed on ts_end): the service must still read as new in :03.
func TestTimelineNewSurvivesFlushMinuteSkew(t *testing.T) {
	base := time.Now().Truncate(time.Minute).Add(-20 * time.Minute)
	srv := timelineTestServer(t, []FlowRecord{
		{TSEnd: base.Add(3 * time.Minute), Client: "alice", RemoteIP: "93.184.216.35", RemotePort: 443,
			Proto: "tcp", Domain: "www.newsite.com", ClientDownloadBytes: 500_000},
		{TSEnd: base.Add(3*time.Minute + 30*time.Second), Client: "alice", RemoteIP: "93.184.216.35", RemotePort: 443,
			Proto: "tcp", Domain: "www.newsite.com", ClientDownloadBytes: 500_000},
		{TSEnd: base.Add(4 * time.Minute), Client: "alice", RemoteIP: "93.184.216.35", RemotePort: 443,
			Proto: "tcp", Domain: "www.newsite.com", ClientDownloadBytes: 500_000},
	})
	webTestWriteJSONL(t, srv.logDir, "tls.jsonl",
		TLSRecord{TS: base.Add(2*time.Minute + 40*time.Second), Client: "alice", RemoteIP: "93.184.216.35", RemotePort: 443, ServerName: "www.newsite.com", Protocol: "tls"},
	)
	tl := timelineGet(t, srv, "alice", "?since=30m")
	fresh, ok := timelineServiceIn(timelineMinuteAt(t, tl, base.Add(3*time.Minute)).Services, "newsite.com")
	if !ok || !fresh.New {
		t.Fatalf("newsite.com should be new in the first row-bearing minute after its handshake: ok=%v row=%+v", ok, fresh)
	}
	later, _ := timelineServiceIn(timelineMinuteAt(t, tl, base.Add(4*time.Minute)).Services, "newsite.com")
	if later.New {
		t.Error("new must be marked once, not on every later minute")
	}
	if len(tl.Sessions) != 1 || len(tl.Sessions[0].NewServices) != 1 || tl.Sessions[0].NewServices[0] != "newsite.com" {
		t.Errorf("sessions = %+v, want one session with new_services [newsite.com]", tl.Sessions)
	}
}

// The advertised 6-hour cap must be reachable by the natural request.
func TestTimelineSixHourWindowRenders(t *testing.T) {
	srv := timelineTestServer(t, []FlowRecord{{TSEnd: time.Now().Truncate(time.Minute).Add(-time.Minute), Client: "bob",
		RemoteIP: "93.184.216.34", RemotePort: 443, Proto: "tcp", Domain: "example.com", ClientDownloadBytes: 1000}})
	tl := timelineGet(t, srv, "alice", "?since=6h")
	if tl.Minutes == nil || tl.Sessions == nil || tl.Note != "" {
		t.Fatalf("since=6h must render (empty lists, no note); got minutes=%v sessions=%v note=%q", tl.Minutes == nil, tl.Sessions == nil, tl.Note)
	}
}
