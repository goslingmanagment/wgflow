package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAliasConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.yaml")
	cfg := `
people:
  - display: Diana
    devices: [diana-iphone, diana-macbook]
  - display: Мама
    devices: [mom-macbook]
device_kind:
  mom-macbook: laptop
`
	if err := os.WriteFile(path, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}
	ac, err := loadAliasConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if ac.Person("diana-iphone") != "Diana" || ac.Person("diana-macbook") != "Diana" {
		t.Errorf("diana devices should map to Diana")
	}
	if ac.Person("mom-macbook") != "Мама" {
		t.Errorf("mom-macbook = %q, want Мама", ac.Person("mom-macbook"))
	}
	if ac.Person("guest-iphone") != "guest" { // unmapped -> prefix fallback
		t.Errorf("unmapped fallback = %q, want guest", ac.Person("guest-iphone"))
	}
	if ac.Person("mom") != "mom" { // hyphenless -> whole name, never orphaned
		t.Errorf("hyphenless fallback = %q, want mom", ac.Person("mom"))
	}
	if ac.Kind("mom-macbook") != "laptop" {
		t.Errorf("kind override = %q, want laptop", ac.Kind("mom-macbook"))
	}
	if ac.Kind("diana-iphone") != "" {
		t.Errorf("no override should be empty")
	}
	if len(ac.Roster()) != 3 {
		t.Errorf("roster = %v, want 3 devices", ac.Roster())
	}
}

func TestAliasConfigFallbacks(t *testing.T) {
	// missing file -> empty (not error), nil receiver -> same fallbacks
	ac, err := loadAliasConfig(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var nilAC *AliasConfig
	for _, a := range []*AliasConfig{ac, nilAC} {
		if a.Person("diana-iphone") != "diana" {
			t.Errorf("fallback Person = %q, want diana", a.Person("diana-iphone"))
		}
		if a.Kind("x") != "" || a.Roster() != nil {
			t.Errorf("empty/nil config should have no kind/roster")
		}
	}
}

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
		{"edec822a8c68.j.cloudfront.hls.ttvnw.net", "", "twitch"}, // named twitch beats AWS fallback
		{"cdn.discordapp.com", "", "discord"},
		{"static.example", "104.29.153.158", "cloudflare"},
		{"d111111abcdef8.cloudfront.net", "", "aws"},
		{"telemetry-in.battle.net", "", "games"},
		{"one.one.one.one", "1.1.1.1", "dns"},
		{"", "37.140.178.106", "yandex"},
		{"", "5.255.221.166", "yandex"},
		{"mcs-normal-sg.capcutapi.com", "", "bytedance"},
		{"p16-heycan-file-sign-sg.ibyteimg.com", "", "bytedance"},
		{"api.vk.com", "", "vk"},
		{"sun9-1.userapi.com", "", "vk"},
		{"ipv4-c001.nflxvideo.net", "", "netflix"},
		{"audio-fa.scdn.co", "", "spotify"},
		{"ctldl.windowsupdate.com", "", "microsoft"},
		{"e1234.dscx.akamaiedge.net", "", "cdn"},
		{"unknown-host.example.org", "", "other"},
	}
	for _, tc := range cases {
		if got := categorize(tc.target, tc.ip, "tcp", 443); got != tc.want {
			t.Fatalf("categorize(%q, %q) = %q, want %q", tc.target, tc.ip, got, tc.want)
		}
	}
}

func TestNewAPIFlowEnrichesKnownBareIPs(t *testing.T) {
	f := newAPIFlow(&TopAgg{
		Client:   "diana-macbook",
		Category: "other",
		Target:   "37.140.178.106",
		Proto:    "tcp",
		Port:     443,
		Down:     100,
		Up:       20,
	})
	if f.Category != "yandex" {
		t.Fatalf("Category = %q, want yandex", f.Category)
	}
	if f.ResolvedTarget != "s106nrg.storage.yandex.net" {
		t.Fatalf("ResolvedTarget = %q", f.ResolvedTarget)
	}
	if f.TargetOrg != "Yandex Storage" {
		t.Fatalf("TargetOrg = %q", f.TargetOrg)
	}
	if !f.IsIP {
		t.Fatalf("IsIP = false, want true")
	}
	if f.Total != 120 {
		t.Fatalf("Total = %d, want 120", f.Total)
	}
}

func TestParseTLSSNI(t *testing.T) {
	record, handshake := testTLSClientHello("upload.example.com")
	if got := parseTLSSNI(record); got != "upload.example.com" {
		t.Fatalf("parseTLSSNI = %q, want upload.example.com", got)
	}
	if got := parseTLSHandshakeSNI(handshake); got != "upload.example.com" {
		t.Fatalf("parseTLSHandshakeSNI = %q, want upload.example.com", got)
	}
}

func TestParseQUICSNI(t *testing.T) {
	packet := testQUICInitialPacket(t, "firebaseappcheck.googleapis.com")
	if got := parseQUICSNI(packet); got != "firebaseappcheck.googleapis.com" {
		t.Fatalf("parseQUICSNI = %q, want firebaseappcheck.googleapis.com", got)
	}
}

func TestParseDNSMessageAnswerNames(t *testing.T) {
	msg := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	msg = appendDNSNameTest(msg, "photos.example.com")
	msg = append(msg, 0x00, 0x01, 0x00, 0x01) // question A IN
	msg = append(msg,
		0xc0, 0x0c, // answer owner -> question name
		0x00, 0x01, // A
		0x00, 0x01, // IN
		0x00, 0x00, 0x01, 0x2c, // TTL 300
		0x00, 0x04,
		192, 0, 2, 55,
	)
	parsed, ok := parseDNSMessage(msg)
	if !ok {
		t.Fatal("parseDNSMessage failed")
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("answers = %d, want 1", len(parsed.Answers))
	}
	ans := parsed.Answers[0]
	if ans.Name != "photos.example.com" || ans.Type != "A" || ans.Value != "192.0.2.55" || ans.TTL != 300 {
		t.Fatalf("answer = %+v", ans)
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

func testTLSClientHello(host string) (record []byte, handshake []byte) {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)                   // session_id
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites
	body = append(body, 0x01, 0x00)             // compression_methods
	serverName := []byte{0x00, byte(len(host) >> 8), byte(len(host))}
	serverName = append(serverName, []byte(host)...)
	sniData := []byte{byte(len(serverName) >> 8), byte(len(serverName))}
	sniData = append(sniData, serverName...)
	ext := []byte{0x00, 0x00, byte(len(sniData) >> 8), byte(len(sniData))}
	ext = append(ext, sniData...)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	handshake = []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record = []byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	record = append(record, handshake...)
	return record, handshake
}

func testQUICInitialPacket(t *testing.T, host string) []byte {
	t.Helper()
	_, handshake := testTLSClientHello(host)
	plain := []byte{0x06, 0x00} // CRYPTO, offset=0
	plain = append(plain, encodeQUICVarIntTest(uint64(len(handshake)))...)
	plain = append(plain, handshake...)
	for len(plain) < 160 {
		plain = append(plain, 0x00)
	}

	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	key, iv, hp, ok := quicInitialKeys(0x00000001, dcid)
	if !ok {
		t.Fatal("missing quic v1 keys")
	}
	header := []byte{0xc0, 0x00, 0x00, 0x00, 0x01, byte(len(dcid))}
	header = append(header, dcid...)
	header = append(header, 0x00) // scid len
	header = append(header, 0x00) // token len
	pn := []byte{0x01}
	header = append(header, encodeQUICVarIntTest(uint64(len(pn)+len(plain)+16))...)
	pnOffset := len(header)
	headerWithPN := append(append([]byte(nil), header...), pn...)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := append([]byte(nil), iv...)
	nonce[len(nonce)-1] ^= 0x01
	packet := append(headerWithPN, aead.Seal(nil, nonce, plain, headerWithPN)...)

	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		t.Fatal(err)
	}
	var mask [aes.BlockSize]byte
	hpBlock.Encrypt(mask[:], packet[pnOffset+4:pnOffset+4+aes.BlockSize])
	packet[0] ^= mask[0] & 0x0f
	packet[pnOffset] ^= mask[1]
	return packet
}

func encodeQUICVarIntTest(v uint64) []byte {
	switch {
	case v < 64:
		return []byte{byte(v)}
	case v < 16384:
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(v)|0x4000)
		return b[:]
	case v < 1073741824:
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(v)|0x80000000)
		return b[:]
	default:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v|0xc000000000000000)
		return b[:]
	}
}

func appendDNSNameTest(dst []byte, name string) []byte {
	for _, label := range strings.Split(name, ".") {
		dst = append(dst, byte(len(label)))
		dst = append(dst, label...)
	}
	return append(dst, 0x00)
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
