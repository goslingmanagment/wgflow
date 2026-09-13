package main

import (
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

func TestRollupPreservesDownloadUploadDirection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollup.db")
	rollup, err := OpenRollup(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rollup.Close()

	// An hour back, but never before today's MSK midnight: clientDayTimeline is
	// midnight-anchored, so just after midnight a "yesterday 23:xx" record would
	// legitimately be absent and the day-timeline assertion below would flake.
	base := time.Now().Add(-time.Hour)
	nowMSK := time.Now().In(mskLocation)
	midnight := time.Date(nowMSK.Year(), nowMSK.Month(), nowMSK.Day(), 0, 0, 0, 0, mskLocation)
	if base.Before(midnight) {
		base = time.Now().Add(-2 * time.Minute)
	}
	base = base.Truncate(time.Minute)
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

func TestNewAPIFlowEnrichesKnownBareIPs(t *testing.T) {
	yandex := newAPIFlow(&TopAgg{
		Client:   "diana-macbook",
		Category: "other",
		Target:   "37.140.178.106",
		Proto:    "tcp",
		Port:     443,
		Down:     100,
		Up:       20,
	})
	if yandex.Category != "yandex" {
		t.Fatalf("Category = %q, want yandex", yandex.Category)
	}
	if yandex.ResolvedTarget != "s106nrg.storage.yandex.net" {
		t.Fatalf("ResolvedTarget = %q", yandex.ResolvedTarget)
	}
	if yandex.TargetOrg != "Yandex Storage" {
		t.Fatalf("TargetOrg = %q", yandex.TargetOrg)
	}
	if !yandex.IsIP {
		t.Fatalf("IsIP = false, want true")
	}
	if yandex.Total != 120 {
		t.Fatalf("Total = %d, want 120", yandex.Total)
	}

	cloudfront := newAPIFlow(&TopAgg{
		Client:   "diana-macbook",
		Category: "other",
		Target:   "3.171.214.100",
		Proto:    "tcp",
		Port:     443,
		Down:     10,
	})
	if cloudfront.Category != "aws" {
		t.Fatalf("cloudfront category = %q, want aws", cloudfront.Category)
	}
	if cloudfront.ResolvedTarget != "server-3-171-214-100.fra50.r.cloudfront.net" {
		t.Fatalf("cloudfront resolved target = %q", cloudfront.ResolvedTarget)
	}
	if cloudfront.TargetOrg != "Amazon CloudFront" {
		t.Fatalf("cloudfront target org = %q", cloudfront.TargetOrg)
	}

	attributed := newAPIFlowWithAttribution(&TopAgg{
		Client:   "diana-macbook",
		Category: "aws",
		Target:   "3.171.214.100",
		Proto:    "tcp",
		Port:     443,
		Down:     10,
	}, map[string]apiFlowAttribution{
		flowAttributionKey("diana-macbook", "3.171.214.100"): {
			AppTarget:  "apiv3.fansly.com",
			Source:     "TLS SNI",
			Candidates: []string{"apiv3.fansly.com"},
		},
	})
	if attributed.Category != "fansly" {
		t.Fatalf("attributed category = %q, want fansly", attributed.Category)
	}
	if attributed.AppTarget != "apiv3.fansly.com" {
		t.Fatalf("attributed app target = %q", attributed.AppTarget)
	}
	if attributed.AttributionSource != "TLS SNI" {
		t.Fatalf("attribution source = %q", attributed.AttributionSource)
	}
}

// The org of a bare IP may name the row; the org of a NAMED row may not touch
// it. The old code appended the org to the name before categorizing, so every
// app behind a CDN read as "aws"/"cloudflare"/"cdn" — the road, not the
// destination. These are the exact probes from that investigation.
func TestNewAPIFlowCategoryUsesOrgOnlyForBareIPs(t *testing.T) {
	const MB = 1 << 20
	cases := []struct {
		name          string
		agg           TopAgg
		app           string
		wantCat       string
		wantService   string
		wantRole      string
		wantDirection string
	}{
		{
			name:          "app on a CloudFront edge is the app, not aws",
			agg:           TopAgg{Client: "diana-iphone", Category: "other", Target: "3.171.214.100", Proto: "udp", Port: 443, Up: 4 * MB, Down: 1 * MB},
			app:           "upload.picsart.com",
			wantCat:       "other",
			wantService:   "picsart.com",
			wantDirection: "upload",
		},
		{
			name:        "app on a Cloudflare edge is the app, not cloudflare",
			agg:         TopAgg{Client: "diana-iphone", Category: "other", Target: "104.29.153.158", Proto: "udp", Port: 443, Down: 2000},
			app:         "upload.picsart.com",
			wantCat:     "other",
			wantService: "picsart.com",
		},
		{
			name:    "bare Akamai IP with no name falls back to its org",
			agg:     TopAgg{Client: "diana-iphone", Category: "other", Target: "2.16.1.1", Proto: "udp", Port: 443, Down: 2000},
			wantCat: "cdn",
		},
		{
			name:    "bare Cloudflare IP with no name stays cloudflare",
			agg:     TopAgg{Client: "diana-iphone", Category: "other", Target: "104.29.153.158", Proto: "udp", Port: 443, Down: 2000},
			wantCat: "cloudflare",
		},
		{
			name:    "a Google Cloud range is a tenant's traffic, not Google's",
			agg:     TopAgg{Client: "diana-iphone", Category: "other", Target: "34.64.1.1", Proto: "udp", Port: 443, Down: 2000},
			wantCat: "other",
		},
		{
			name:        "named row heals a stored cloudflare label even down to other",
			agg:         TopAgg{Client: "diana-iphone", Category: "cloudflare", Target: "static.example", Proto: "tcp", Port: 443, Down: 2000},
			wantCat:     "other",
			wantService: "static.example", // unknown host: it names itself, nothing is invented
		},
		{
			name:        "named ad SDK wins over a stored infra label",
			agg:         TopAgg{Client: "diana-iphone", Category: "cloudflare", Target: "ms.applovin.com", Proto: "tcp", Port: 443, Down: 2000},
			wantCat:     "ads",
			wantService: "AppLovin",
			wantRole:    roleAds,
		},
		{
			name:          "media row keeps its brand and reports a download",
			agg:           TopAgg{Client: "diana-iphone", Category: "", Target: "rr4---sn-1.googlevideo.com", Proto: "tcp", Port: 443, Down: 20 * MB, Up: 100 << 10},
			wantCat:       "google",
			wantService:   "YouTube",
			wantRole:      roleMedia,
			wantDirection: "download",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agg := tc.agg
			var attrs map[string]apiFlowAttribution
			if tc.app != "" {
				attrs = map[string]apiFlowAttribution{
					flowAttributionKey(agg.Client, agg.Target): {AppTarget: tc.app, Source: "TLS SNI"},
				}
			}
			f := newAPIFlowWithAttribution(&agg, attrs)
			if f.Category != tc.wantCat {
				t.Errorf("category = %q, want %q (org=%q)", f.Category, tc.wantCat, f.TargetOrg)
			}
			if f.Service != tc.wantService {
				t.Errorf("service = %q, want %q", f.Service, tc.wantService)
			}
			if f.Role != tc.wantRole {
				t.Errorf("role = %q, want %q", f.Role, tc.wantRole)
			}
			if f.Direction != tc.wantDirection {
				t.Errorf("direction = %q, want %q", f.Direction, tc.wantDirection)
			}
		})
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

func TestClientMinuteRibbon(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollup.db")
	rollup, err := OpenRollup(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rollup.Close()

	base := time.Now().Add(-4 * time.Minute).Truncate(time.Minute)
	recs := []FlowRecord{
		// minute 0: 2 MB Yandex -> >1MB flag
		{TSEnd: base, Client: "diana-iphone", RemoteIP: "87.250.250.242", RemotePort: 443, Proto: "tcp", Domain: "api.music.yandex.net", ClientDownloadBytes: 2 << 20},
		// minute +2: 50 KB Apple -> below the 100KB flag
		{TSEnd: base.Add(2 * time.Minute), Client: "diana-iphone", RemoteIP: "17.57.144.22", RemotePort: 443, Proto: "tcp", Domain: "gateway.icloud.com", ClientDownloadBytes: 50 << 10},
	}
	if err := rollup.Add(recs); err != nil {
		t.Fatal(err)
	}
	srv := &webServer{rollupPath: path}
	// window [base-1, base+3] -> 5 minutes; idx1=base, idx3=base+2, rest silent
	mins := srv.clientMinuteRibbon("diana-iphone", base.Add(-time.Minute), base.Add(3*time.Minute))
	if len(mins) != 5 {
		t.Fatalf("ribbon len = %d, want 5", len(mins))
	}
	if !mins[1].Over1M || !mins[1].Over100K || mins[1].TopCategory != "yandex" {
		t.Errorf("minute 1 = %+v, want 2MB yandex flagged", mins[1])
	}
	if mins[3].Over100K || mins[3].Over1M {
		t.Errorf("minute 3 (50KB) must not be flagged: %+v", mins[3])
	}
	if mins[3].TopCategory != "apple" {
		t.Errorf("minute 3 category = %q, want apple", mins[3].TopCategory)
	}
	if mins[0].Bytes != 0 || mins[2].Bytes != 0 || mins[4].Bytes != 0 {
		t.Errorf("silent minutes must be zero-filled: %+v %+v %+v", mins[0], mins[2], mins[4])
	}
}

func TestParseRange(t *testing.T) {
	mk := func(q string) *http.Request { return httptest.NewRequest(http.MethodGet, "/x?"+q, nil) }
	if _, _, ok := parseRange(mk("since=5m")); ok {
		t.Error("no from -> ok should be false")
	}
	from, to, ok := parseRange(mk("from=1782560000&to=1782561000"))
	if !ok || from.Unix() != 1782560000 || to.Unix() != 1782561000 {
		t.Errorf("from/to = %d..%d ok=%v", from.Unix(), to.Unix(), ok)
	}
	if _, _, ok := parseRange(mk("from=1782561000&to=1782560000")); ok {
		t.Error("to<=from -> ok should be false")
	}
}

func TestClientDetailRecentHonorsTo(t *testing.T) {
	logDir := t.TempDir()
	writeJSONL := func(name string, vals ...any) {
		t.Helper()
		f, err := os.Create(filepath.Join(logDir, name))
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

	to := time.Now().Truncate(time.Second)
	from := to.Add(-5 * time.Minute)
	inside := to.Add(-1 * time.Minute)
	future := to.Add(1 * time.Minute)
	writeJSONL("tls.jsonl",
		TLSRecord{TS: inside, Client: "alice", ServerName: "inside.example", RemotePort: 443},
		TLSRecord{TS: future, Client: "alice", ServerName: "future.example", RemotePort: 443},
	)
	writeJSONL("dns.jsonl",
		DNSRecord{TS: inside, Client: "alice", Query: "inside.example", QType: "A"},
		DNSRecord{TS: future, Client: "alice", Query: "future.example", QType: "A"},
	)

	srv := &webServer{logDir: logDir, rollupPath: filepath.Join(t.TempDir(), "missing.db")}
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/clients/alice?from=%d&to=%d", from.Unix(), to.Unix()), nil)
	rec := httptest.NewRecorder()
	srv.handleClientDetail(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var got struct {
		RecentTLS []TLSRecord `json:"recent_tls"`
		RecentDNS []DNSRecord `json:"recent_dns"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.RecentTLS) != 1 || got.RecentTLS[0].ServerName != "inside.example" {
		t.Fatalf("recent_tls = %+v, want only inside.example", got.RecentTLS)
	}
	if len(got.RecentDNS) != 1 || got.RecentDNS[0].Query != "inside.example" {
		t.Fatalf("recent_dns = %+v, want only inside.example", got.RecentDNS)
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
		sdkHits        int
		devKind        string
		lastTLS        time.Time
		loggerOK       bool
		wantStatus     string
		wantConfidence string
		wantSDKReason  bool
	}{
		{"silent confirmed", []uint64{0, 0, 0}, 0, nil, 0, "phone", zero, true, "silent", "high", false},
		{"silent unconfirmed (logger down)", []uint64{0, 0, 0}, 0, nil, 0, "phone", zero, false, "silent", "low", false},
		{"sustained stream on phone", []uint64{2 * MB, 2 * MB, 3 * MB}, 7 * MB, cat("yandex", 7*MB), 0, "phone", fresh, true, "active", "high", false},
		{"sustained stream on laptop is softer", []uint64{2 * MB, 2 * MB}, 4 * MB, cat("yandex", 4*MB), 0, "laptop", zero, true, "active", "medium", false},
		{"tens of MB in one burst", []uint64{25 * MB}, 25 * MB, cat("google", 25*MB), 0, "phone", zero, true, "active", "high", false},
		{"fresh TLS to non-background", []uint64{200 * KB}, 200 * KB, cat("meta", 200*KB), 0, "phone", fresh, true, "active", "medium", false},
		{"apple-only small is background", []uint64{30 * KB, 25 * KB}, 55 * KB, cat("apple", 55*KB), 0, "laptop", zero, true, "likely-background", "high", false},
		{"small non-background, no fresh trace", []uint64{150 * KB}, 150 * KB, cat("meta", 150*KB), 0, "phone", zero, true, "likely-background", "low", false},
		// SDK hosts annotate the volume rules without changing their verdict.
		{"stream with ad SDKs still high", []uint64{2 * MB, 2 * MB, 3 * MB}, 7 * MB, cat("ads", 7*MB), 5, "phone", fresh, true, "active", "high", true},
		{"burst with ad SDKs", []uint64{25 * MB}, 25 * MB, cat("ads", 25*MB), 3, "phone", zero, true, "active", "high", true},
		// The new case: too small for the byte rules, but ad SDKs do not run
		// on their own — one >100KB minute or a fresh trace is enough.
		{"ad SDKs + one significant minute", []uint64{150 * KB}, 150 * KB, cat("ads", 150*KB), 7, "phone", zero, true, "active", "medium", true},
		{"ad SDKs on a laptop are softer", []uint64{150 * KB}, 150 * KB, cat("ads", 150*KB), 7, "laptop", zero, true, "active", "low", true},
		{"ad SDKs behind apple-only, fresh trace", []uint64{40 * KB}, 40 * KB, cat("apple", 40*KB), 2, "phone", fresh, true, "active", "medium", true},
		// Without a fresh trace or a significant minute the SDK hint is not
		// enough on its own: no rule invents activity from a whisper.
		{"ad SDKs but only a whisper", []uint64{40 * KB}, 40 * KB, cat("ads", 40*KB), 2, "phone", zero, true, "likely-background", "low", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := classify(tc.series, start, tc.total, tc.cats, tc.sdkHits, tc.devKind, tc.lastTLS, zero, now, tc.loggerOK)
			if v.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q (reasons: %v)", v.Status, tc.wantStatus, v.Reasons)
			}
			if v.Confidence != tc.wantConfidence {
				t.Errorf("confidence = %q, want %q (reasons: %v)", v.Confidence, tc.wantConfidence, v.Reasons)
			}
			if len(v.Reasons) == 0 {
				t.Errorf("verdict has no reasons — every classification must explain its firing rule")
			}
			if v.Evidence.SDKHits != tc.sdkHits {
				t.Errorf("evidence.sdk_hits = %d, want %d", v.Evidence.SDKHits, tc.sdkHits)
			}
			gotSDKReason := false
			for _, r := range v.Reasons {
				if strings.Contains(r, "SDK рекламы/аналитики") {
					gotSDKReason = true
				}
			}
			if gotSDKReason != tc.wantSDKReason {
				t.Errorf("SDK reason present = %v, want %v (reasons: %v)", gotSDKReason, tc.wantSDKReason, v.Reasons)
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
	v := classify(series, start, 2*MB+40*KB, []apiCatShare{{Category: "yandex", Bytes: 2 * MB}}, 0, "phone", time.Time{}, time.Time{}, now, true)
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
