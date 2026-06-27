package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestClientMapMatchDirection(t *testing.T) {
	_, vpn, err := net.ParseCIDR("10.66.66.0/24")
	if err != nil {
		t.Fatal(err)
	}
	clients := &ClientMap{
		byIP:    map[string]string{"10.66.66.6": "alice"},
		vpnNets: []*net.IPNet{vpn},
	}

	clientIP, name, outbound, ok := clients.Match(net.ParseIP("10.66.66.6"), net.ParseIP("8.8.8.8"))
	if !ok || !outbound || clientIP != "10.66.66.6" || name != "alice" {
		t.Fatalf("outbound match = (%q, %q, %v, %v)", clientIP, name, outbound, ok)
	}

	clientIP, name, outbound, ok = clients.Match(net.ParseIP("8.8.8.8"), net.ParseIP("10.66.66.6"))
	if !ok || outbound || clientIP != "10.66.66.6" || name != "alice" {
		t.Fatalf("inbound match = (%q, %q, %v, %v)", clientIP, name, outbound, ok)
	}
}

func TestRollupPreservesDownloadUploadDirection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollup.db")
	rollup, err := OpenRollup(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rollup.Close()

	base := time.Now().Add(-time.Hour).Truncate(time.Minute)
	records := []FlowRecord{
		{
			TSEnd: base, Client: "alice", ClientIP: "10.66.66.6",
			RemoteIP: "93.184.216.34", RemotePort: 443, Proto: "tcp", Domain: "example.com",
			ClientDownloadBytes: 1000, ClientUploadBytes: 200,
			ClientDownloadPackets: 10, ClientUploadPackets: 2,
		},
		{
			TSEnd: base.Add(10 * time.Second), Client: "alice", ClientIP: "10.66.66.6",
			RemoteIP: "93.184.216.34", RemotePort: 443, Proto: "tcp", Domain: "example.com",
			ClientDownloadBytes: 300, ClientUploadBytes: 40,
			ClientDownloadPackets: 3, ClientUploadPackets: 1,
		},
		{
			TSEnd: base, Client: "bob", ClientIP: "10.66.66.7",
			RemoteIP: "149.154.167.223", RemotePort: 443, Proto: "tcp",
			ClientDownloadBytes: 500, ClientUploadBytes: 50,
			ClientDownloadPackets: 5, ClientUploadPackets: 1,
		},
	}
	if err := rollup.Add(records); err != nil {
		t.Fatal(err)
	}

	aggs := map[string]*TopAgg{}
	rows, err := aggregateFromRollup(path, base.Add(-time.Minute), "", aggs)
	if err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("rollup rows = %d, want 2", rows)
	}

	alice := findAgg(t, aggs, "alice", "other", "example.com", "tcp", 443)
	if alice.Down != 1300 || alice.Up != 240 || alice.DownP != 13 || alice.UpP != 3 {
		t.Fatalf("alice aggregate = down=%d up=%d downP=%d upP=%d", alice.Down, alice.Up, alice.DownP, alice.UpP)
	}

	bob := findAgg(t, aggs, "bob", "telegram", "149.154.167.223", "tcp", 443)
	if bob.Down != 500 || bob.Up != 50 || bob.DownP != 5 || bob.UpP != 1 {
		t.Fatalf("bob aggregate = down=%d up=%d downP=%d upP=%d", bob.Down, bob.Up, bob.DownP, bob.UpP)
	}

	byClient, byCategory, totalRows, err := aggregateReportTotalsFromRollup(path, base.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if totalRows != 4 {
		t.Fatalf("total rows = %d, want 4", totalRows)
	}
	if byClient["alice"].Down != 1300 || byClient["alice"].Up != 240 {
		t.Fatalf("alice totals = down=%d up=%d", byClient["alice"].Down, byClient["alice"].Up)
	}
	if byCategory["telegram"].Down != 500 || byCategory["telegram"].Up != 50 {
		t.Fatalf("telegram totals = down=%d up=%d", byCategory["telegram"].Down, byCategory["telegram"].Up)
	}

	srv := &webServer{rollupPath: path}
	day := srv.clientDayTimeline("alice")
	hour := base.In(mskLocation).Hour()
	if day[hour].Total != 1540 || day[hour].Cats["other"] != 1540 {
		t.Fatalf("alice day bucket = total=%d other=%d", day[hour].Total, day[hour].Cats["other"])
	}
}

func TestMSKHourBucketing(t *testing.T) {
	// Host-independent: each UTC instant must land in its Moscow (UTC+3) hour
	// bucket no matter what TZ the test process runs under.
	cases := []struct {
		utc  string
		want int
	}{
		{"2026-01-15T23:30:00Z", 2},  // 02:30 MSK next day
		{"2026-06-15T21:00:00Z", 0},  // 00:00 MSK next day
		{"2026-06-15T09:15:00Z", 12}, // 12:15 MSK
	}
	for _, tc := range cases {
		ts, err := time.Parse(time.RFC3339, tc.utc)
		if err != nil {
			t.Fatal(err)
		}
		if got := mskHour(ts.Unix() / 60); got != tc.want {
			t.Fatalf("mskHour(%s) = %d, want %d", tc.utc, got, tc.want)
		}
	}
}

func TestThroughputSeriesIncludesZeroMinutes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollup.db")
	rollup, err := OpenRollup(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rollup.Close()

	base := time.Now().Add(-10 * time.Minute).Truncate(time.Minute)
	records := []FlowRecord{
		{
			TSEnd: base, Client: "alice", ClientIP: "10.66.66.6",
			RemoteIP: "93.184.216.34", RemotePort: 443, Proto: "tcp",
			ClientDownloadBytes: 1000, ClientUploadBytes: 200,
		},
		{
			TSEnd: base.Add(2 * time.Minute), Client: "alice", ClientIP: "10.66.66.6",
			RemoteIP: "93.184.216.34", RemotePort: 443, Proto: "tcp",
			ClientDownloadBytes: 300, ClientUploadBytes: 40,
		},
	}
	if err := rollup.Add(records); err != nil {
		t.Fatal(err)
	}

	srv := &webServer{rollupPath: path}
	points := srv.throughputSeries(base, base.Add(2*time.Minute))
	if len(points) != 3 {
		t.Fatalf("points len = %d, want 3", len(points))
	}
	if points[0].Down != 1000 || points[0].Up != 200 {
		t.Fatalf("point 0 = down=%d up=%d", points[0].Down, points[0].Up)
	}
	if points[1].Down != 0 || points[1].Up != 0 {
		t.Fatalf("point 1 = down=%d up=%d, want zero gap", points[1].Down, points[1].Up)
	}
	if points[2].Down != 300 || points[2].Up != 40 {
		t.Fatalf("point 2 = down=%d up=%d", points[2].Down, points[2].Up)
	}
}

func TestCategorizeCommonInfrastructure(t *testing.T) {
	cases := []struct {
		target string
		ip     string
		want   string
	}{
		{"edec822a8c68.j.cloudfront.hls.ttvnw.net", "", "twitch"},
		{"cdn.discordapp.com", "", "discord"},
		{"static.example", "104.29.153.158", "cloudflare"},
		{"d111111abcdef8.cloudfront.net", "", "aws"},
		{"telemetry-in.battle.net", "", "games"},
		{"one.one.one.one", "1.1.1.1", "dns"},
	}
	for _, tc := range cases {
		if got := categorize(tc.target, tc.ip, "tcp", 443); got != tc.want {
			t.Fatalf("categorize(%q, %q) = %q, want %q", tc.target, tc.ip, got, tc.want)
		}
	}
}

func TestSnapshotFromRollup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollup.db")
	rollup, err := OpenRollup(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rollup.Close()

	base := time.Now().Add(-3 * time.Minute).Truncate(time.Minute)
	recs := []FlowRecord{
		// minute 0: 2 MB download from Yandex Music
		{TSEnd: base, Client: "diana-iphone", RemoteIP: "87.250.250.242", RemotePort: 443, Proto: "tcp", Domain: "api.music.yandex.net", ClientDownloadBytes: 2 << 20},
		// minute 2: 300 KB down + 20 KB up to Instagram
		{TSEnd: base.Add(2 * time.Minute), Client: "diana-iphone", RemoteIP: "157.240.1.1", RemotePort: 443, Proto: "tcp", Domain: "scontent.cdninstagram.com", ClientDownloadBytes: 300 << 10, ClientUploadBytes: 20 << 10},
	}
	if err := rollup.Add(recs); err != nil {
		t.Fatal(err)
	}
	srv := &webServer{rollupPath: path}
	snaps := srv.snapshotFromRollup(base.Add(-time.Minute), base.Add(2*time.Minute))
	sc := snaps["diana-iphone"]
	if sc == nil {
		t.Fatal("missing diana-iphone snapshot")
	}
	if want := uint64(2<<20) + uint64(300<<10); sc.down != want {
		t.Errorf("down = %d, want %d", sc.down, want)
	}
	if sc.up != 20<<10 {
		t.Errorf("up = %d, want %d", sc.up, 20<<10)
	}
	if sc.minOver1mb != 1 {
		t.Errorf("minOver1mb = %d, want 1", sc.minOver1mb)
	}
	if sc.minOver100k != 2 {
		t.Errorf("minOver100k = %d, want 2", sc.minOver100k)
	}
	if sc.cats["yandex"] != 2<<20 {
		t.Errorf("cats[yandex] = %d, want %d", sc.cats["yandex"], 2<<20)
	}
	if want := uint64(300<<10) + uint64(20<<10); sc.cats["meta"] != want {
		t.Errorf("cats[meta] = %d, want %d", sc.cats["meta"], want)
	}
}

func TestDeviceKind(t *testing.T) {
	cases := map[string]string{
		"diana-iphone": "phone",
		"anya-ipad":    "phone",
		"kid-android":  "phone",
		"mom-macbook":  "laptop",
		"dad-pc":       "laptop",
		"office-imac":  "laptop",
		"work-desktop": "laptop",
		"mom":          "",
		"guest":        "",
	}
	for name, want := range cases {
		if got := deviceKind(name); got != want {
			t.Errorf("deviceKind(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestIsBackgroundOnly(t *testing.T) {
	cases := []struct {
		cats []apiCatShare
		want bool
	}{
		{[]apiCatShare{{Category: "apple", Bytes: 100}, {Category: "dns", Bytes: 50}}, true},
		{[]apiCatShare{{Category: "apple", Bytes: 100}, {Category: "meta", Bytes: 50}}, false},
		{[]apiCatShare{{Category: "yandex", Bytes: 100}}, false},
		{[]apiCatShare{{Category: "apple", Bytes: 0}}, false}, // no non-zero cats -> not background, it's empty
		{nil, false},
	}
	for i, tc := range cases {
		if got := isBackgroundOnly(tc.cats); got != tc.want {
			t.Errorf("case %d: isBackgroundOnly = %v, want %v", i, got, tc.want)
		}
	}
}

func TestClassifyRules(t *testing.T) {
	const KB, MB = 1 << 10, 1 << 20
	now := time.Now()
	start := now.Add(-15*time.Minute).Unix() / 60
	fresh := now.Add(-1 * time.Minute)
	var zero time.Time
	cat := func(c string, b uint64) []apiCatShare { return []apiCatShare{{Category: c, Bytes: b}} }

	cases := []struct {
		name           string
		series         []uint64
		total          uint64
		cats           []apiCatShare
		devKind        string
		lastTLS        time.Time
		loggerOK       bool
		wantStatus     string
		wantConfidence string
	}{
		{"silent confirmed", []uint64{0, 0, 0}, 0, nil, "phone", zero, true, "silent", "high"},
		{"silent unconfirmed (logger down)", []uint64{0, 0, 0}, 0, nil, "phone", zero, false, "silent", "low"},
		{"sustained stream on phone", []uint64{2 * MB, 2 * MB, 3 * MB}, 7 * MB, cat("yandex", 7*MB), "phone", fresh, true, "active", "high"},
		{"sustained stream on laptop is softer", []uint64{2 * MB, 2 * MB}, 4 * MB, cat("yandex", 4*MB), "laptop", zero, true, "active", "medium"},
		{"tens of MB in one burst", []uint64{25 * MB}, 25 * MB, cat("google", 25*MB), "phone", zero, true, "active", "high"},
		{"fresh TLS to non-background", []uint64{200 * KB}, 200 * KB, cat("meta", 200*KB), "phone", fresh, true, "active", "medium"},
		{"apple-only small is background", []uint64{30 * KB, 25 * KB}, 55 * KB, cat("apple", 55*KB), "laptop", zero, true, "likely-background", "high"},
		{"small non-background, no fresh trace", []uint64{150 * KB}, 150 * KB, cat("meta", 150*KB), "phone", zero, true, "likely-background", "low"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := classify(tc.series, start, tc.total, tc.cats, tc.devKind, tc.lastTLS, zero, now, tc.loggerOK)
			if v.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q (reasons: %v)", v.Status, tc.wantStatus, v.Reasons)
			}
			if v.Confidence != tc.wantConfidence {
				t.Errorf("confidence = %q, want %q (reasons: %v)", v.Confidence, tc.wantConfidence, v.Reasons)
			}
			if len(v.Reasons) == 0 {
				t.Errorf("verdict has no reasons — every classification must explain its firing rule")
			}
		})
	}
}

func TestClassifyTracksLastSignificant(t *testing.T) {
	const KB, MB = 1 << 10, 1 << 20
	now := time.Now()
	start := now.Add(-5*time.Minute).Unix() / 60
	// minutes: [push, big, push, quiet, quiet] -> last >100KB is index 1
	series := []uint64{20 * KB, 2 * MB, 20 * KB, 0, 0}
	v := classify(series, start, 2*MB+40*KB, []apiCatShare{{Category: "yandex", Bytes: 2 * MB}}, "phone", time.Time{}, time.Time{}, now, true)
	if v.LastSignificantAt == nil {
		t.Fatal("expected a last_significant_at")
	}
	wantSig := time.Unix((start+1)*60, 0)
	if !v.LastSignificantAt.Equal(wantSig) {
		t.Errorf("last_significant_at = %v, want %v", v.LastSignificantAt, wantSig)
	}
	// last_any_at must be the later push (index 2), separating "last online" from "last real use"
	if v.Evidence.LastAnyAt == nil || !v.Evidence.LastAnyAt.Equal(time.Unix((start+2)*60, 0)) {
		t.Errorf("last_any_at = %v, want %v", v.Evidence.LastAnyAt, time.Unix((start+2)*60, 0))
	}
}

func TestBasicAuthHandler(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := basicAuthHandler(next, "secret", `wg"flow`)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Basic realm="wgflow", charset="UTF-8"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("anything", "wrong")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("anything", "secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("correct password status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func findAgg(t *testing.T, aggs map[string]*TopAgg, client, category, target, proto string, port uint16) *TopAgg {
	t.Helper()
	for _, agg := range aggs {
		if agg.Client == client && agg.Category == category && agg.Target == target && agg.Proto == proto && agg.Port == port {
			return agg
		}
	}
	t.Fatalf("missing aggregate for client=%s category=%s target=%s proto=%s port=%d", client, category, target, proto, port)
	return nil
}
