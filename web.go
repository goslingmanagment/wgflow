package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

//go:embed all:webui/dist
var webAssets embed.FS

// mskLocation pins server-side hour bucketing to Moscow time so the day timeline
// never leaks the host TZ. Moscow has had no DST since 2014, so the FixedZone
// fallback (for hosts shipped without tzdata) stays correct.
var mskLocation = loadMSK()

func loadMSK() *time.Location {
	if loc, err := time.LoadLocation("Europe/Moscow"); err == nil {
		return loc
	}
	return time.FixedZone("MSK", 3*60*60)
}

// mskHour maps a unix-minute bucket to its hour-of-day (0–23) in Moscow time.
func mskHour(unixMinute int64) int {
	return time.Unix(unixMinute*60, 0).In(mskLocation).Hour()
}

type webServer struct {
	logDir     string
	rollupPath string
	wgConfig   string
	iface      string
	aliases    *AliasConfig
}

// resolveDeviceKind prefers the clients.yaml override, then the name-suffix guess.
func (s *webServer) resolveDeviceKind(name string) string {
	if k := s.aliases.Kind(name); k != "" {
		return k
	}
	return deviceKind(name)
}

func webCmd(args []string) error {
	fset := flag.NewFlagSet("web", flag.ExitOnError)
	listen := fset.String("listen", ":8080", "listen address")
	logDir := fset.String("log-dir", "/var/log/wgflow", "log directory")
	rollupPath := fset.String("rollup", "/var/lib/wgflow/rollup.db", "rollup DB path")
	wgConfig := fset.String("wg-config", "/etc/wireguard/wg0.conf", "WireGuard config path")
	iface := fset.String("iface", "wg0", "interface label")
	clientsConfig := fset.String("clients-config", "/etc/wgflow/clients.yaml", "client alias config for person grouping (optional)")
	authPassword := fset.String("auth-password", os.Getenv("WGFLOW_WEB_PASSWORD"), "HTTP Basic Auth password; defaults to WGFLOW_WEB_PASSWORD")
	authRealm := fset.String("auth-realm", "wgflow", "HTTP Basic Auth realm")
	if err := fset.Parse(args); err != nil {
		return err
	}
	aliases, err := loadAliasConfig(*clientsConfig)
	if err != nil {
		return fmt.Errorf("clients-config %s: %w", *clientsConfig, err)
	}
	s := &webServer{logDir: *logDir, rollupPath: *rollupPath, wgConfig: *wgConfig, iface: *iface, aliases: aliases}
	log.Printf("clients-config=%s people=%d devices=%d", *clientsConfig, len(aliases.people), len(aliases.roster))
	mux := http.NewServeMux()
	s.routes(mux)
	handler := http.Handler(mux)
	if *authPassword != "" {
		handler = basicAuthHandler(handler, *authPassword, *authRealm)
	}
	log.Printf("wgflow web listening on %s (log-dir=%s rollup=%s auth=%t)", *listen, *logDir, *rollupPath, *authPassword != "")
	return http.ListenAndServe(*listen, handler)
}

func (s *webServer) routes(mux *http.ServeMux) {
	mux.HandleFunc("/api/system", s.handleSystem)
	mux.HandleFunc("/api/throughput", s.handleThroughput)
	mux.HandleFunc("/api/clients", s.handleClients)
	mux.HandleFunc("/api/clients/", s.handleClientDetail)
	mux.HandleFunc("/api/snapshot", s.handleSnapshot)
	mux.HandleFunc("/api/traffic", s.handleTraffic)
	mux.HandleFunc("/api/categories", s.handleCategories)
	mux.HandleFunc("/api/dns", s.handleDNS)
	mux.HandleFunc("/api/tls", s.handleTLS)
	mux.HandleFunc("/api/report", s.handleReport)
	mux.HandleFunc("/api/stats/stream", s.handleStatsStream)
	mux.Handle("/", s.staticHandler())
}

func basicAuthHandler(next http.Handler, password, realm string) http.Handler {
	passwordHash := sha256.Sum256([]byte(password))
	realm = strings.ReplaceAll(realm, `"`, "")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, gotPassword, ok := r.BasicAuth()
		gotHash := sha256.Sum256([]byte(gotPassword))
		if !ok || subtle.ConstantTimeCompare(gotHash[:], passwordHash[:]) != 1 {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s", charset="UTF-8"`, realm))
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *webServer) staticHandler() http.Handler {
	dist, err := fs.Sub(webAssets, "webui/dist")
	if err != nil {
		log.Printf("web assets unavailable: %v", err)
	}
	fileServer := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if f, err := dist.Open(p); err == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		b, err := fs.ReadFile(dist, "index.html")
		if err != nil {
			http.Error(w, "ui not built", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func parseSince(r *http.Request, def time.Duration) time.Duration {
	v := r.URL.Query().Get("since")
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func parseTimeParam(v string) (time.Time, bool) {
	if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
		return time.Unix(n, 0), true
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// parseRange reads an absolute window from ?from=&to= (unix seconds or RFC3339);
// `to` defaults to now. ok=false when no usable from is present, so callers fall
// back to the relative ?since=. This is what powers "после 02:05".
func parseRange(r *http.Request) (from, to time.Time, ok bool) {
	from, ok = parseTimeParam(r.URL.Query().Get("from"))
	if !ok {
		return time.Time{}, time.Time{}, false
	}
	to = time.Now()
	if t, ok2 := parseTimeParam(r.URL.Query().Get("to")); ok2 {
		to = t
	}
	if !to.After(from) {
		return time.Time{}, time.Time{}, false
	}
	return from, to, true
}

// windowFromRequest yields the effective [from, to]: an absolute from/to if
// given, else now-since..now.
func windowFromRequest(r *http.Request, def time.Duration) (from, to time.Time) {
	if f, t, ok := parseRange(r); ok {
		return f, t
	}
	now := time.Now()
	return now.Add(-parseSince(r, def)), now
}

func topKey(m map[string]uint64) string {
	best := ""
	var bv uint64
	for k, v := range m {
		if v > bv {
			bv = v
			best = k
		}
	}
	return best
}

func mapToShares(m map[string]uint64) []apiCatShare {
	out := make([]apiCatShare, 0, len(m))
	for k, v := range m {
		out = append(out, apiCatShare{Category: k, Bytes: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	return out
}

type apiCatShare struct {
	Category string `json:"category"`
	Bytes    uint64 `json:"bytes"`
}

type apiFlow struct {
	Client   string `json:"client"`
	Category string `json:"category"`
	Target   string `json:"target"`
	Proto    string `json:"proto"`
	Port     uint16 `json:"port"`
	Down     uint64 `json:"down"`
	Up       uint64 `json:"up"`
	Total    uint64 `json:"total"`
	// IsIP marks a target we could not resolve to a hostname (no SNI, no DNS) —
	// usually QUIC. The UI labels these "no hostname (QUIC)" instead of showing a
	// bare IP that reads like a fabricated or missing domain.
	IsIP bool `json:"is_ip"`
}

func newAPIFlow(a *TopAgg) apiFlow {
	return apiFlow{
		Client: a.Client, Category: a.Category, Target: a.Target, Proto: a.Proto, Port: a.Port,
		Down: a.Down, Up: a.Up, Total: a.Down + a.Up, IsIP: net.ParseIP(a.Target) != nil,
	}
}

type apiClient struct {
	Name        string        `json:"name"`
	Down        uint64        `json:"down"`
	Up          uint64        `json:"up"`
	Total       uint64        `json:"total"`
	TopCategory string        `json:"top_category"`
	CurrentSite string        `json:"current_site"`
	Series      []uint64      `json:"series"`
	Cats        []apiCatShare `json:"cats"`
	DeviceKind  string        `json:"device_kind"`
	Person      string        `json:"person"`
	Verdict     *apiVerdict   `json:"verdict,omitempty"`
}

// apiVerdict is the rich, falsifiable output of the classifier. It describes the
// DEVICE's traffic, never human intent: every reason is the exact rule that
// fired so the UI can render "· inferred", and SILENT is only trustworthy when
// logger_ok (surfaced at the response top level) is true.
type apiVerdict struct {
	Status            string      `json:"status"`     // active | likely-background | silent
	Confidence        string      `json:"confidence"` // low | medium | high
	Reasons           []string    `json:"reasons"`
	LastSignificantAt *time.Time  `json:"last_significant_at,omitempty"` // last >100KB minute — last "real use" trace
	Evidence          apiEvidence `json:"evidence"`
}

type apiEvidence struct {
	LastAnyAt    *time.Time `json:"last_any_at,omitempty"` // last minute with any bytes (incl. a lone push)
	LastTLS      *time.Time `json:"last_tls,omitempty"`
	LastDNS      *time.Time `json:"last_dns,omitempty"`
	MinOver1MB   int        `json:"min_over_1mb"`
	MinOver100KB int        `json:"min_over_100kb"`
	DeviceKind   string     `json:"device_kind"`
	TotalBytes   uint64     `json:"total_bytes"`
	FreshTLSDNS  bool       `json:"fresh_tls_dns"` // a TLS or DNS trace within ~3 min
}

// deviceKind infers phone/laptop from the WireGuard peer name. Heuristic; an
// explicit clients.yaml override will supersede it later (roadmap step 5).
func deviceKind(name string) string {
	n := strings.ToLower(name)
	switch {
	case containsAnyStr(n, "iphone", "ipad", "ipod", "phone", "android", "pixel"):
		return "phone"
	case containsAnyStr(n, "macbook", "imac", "mac", "laptop", "desktop", "windows", "linux", "-pc"):
		return "laptop"
	default:
		return ""
	}
}

func containsAnyStr(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// backgroundCats, on their own, usually mean OS chatter (push, cert checks, DNS)
// rather than a person using the device. apple is included but stays hedged: it
// also covers Apple Music / iCloud, which we cannot distinguish from metadata.
var backgroundCats = map[string]bool{"apple": true, "dns": true}

func isBackgroundOnly(cats []apiCatShare) bool {
	seen := false
	for _, c := range cats {
		if c.Bytes == 0 {
			continue
		}
		seen = true
		if !backgroundCats[c.Category] {
			return false
		}
	}
	return seen
}

func freshWithin(t, now time.Time, d time.Duration) bool {
	return !t.IsZero() && now.Sub(t) >= 0 && now.Sub(t) < d
}

// classify is the verdict engine: heuristic, always hedged, never asserting that
// a human acted. It reads the cheap per-minute byte series plus last TLS/DNS
// freshness and the device kind. SILENT requires loggerOK so an outage is never
// branded as quiet.
func classify(series []uint64, startMinute int64, total uint64, cats []apiCatShare, devKind string, lastTLS, lastDNS, now time.Time, loggerOK bool) apiVerdict {
	const kb, mb = 1 << 10, 1 << 20
	var minOver1MB, minOver100KB int
	var lastAnyMin, lastSigMin int64 = -1, -1
	for i, b := range series {
		if b == 0 {
			continue
		}
		lastAnyMin = startMinute + int64(i)
		if b > 100*kb {
			minOver100KB++
			lastSigMin = startMinute + int64(i)
		}
		if b > mb {
			minOver1MB++
		}
	}
	fresh := freshWithin(lastTLS, now, 3*time.Minute) || freshWithin(lastDNS, now, 3*time.Minute)
	ev := apiEvidence{
		MinOver1MB: minOver1MB, MinOver100KB: minOver100KB,
		DeviceKind: devKind, TotalBytes: total, FreshTLSDNS: fresh,
	}
	if lastAnyMin >= 0 {
		t := time.Unix(lastAnyMin*60, 0)
		ev.LastAnyAt = &t
	}
	if !lastTLS.IsZero() {
		t := lastTLS
		ev.LastTLS = &t
	}
	if !lastDNS.IsZero() {
		t := lastDNS
		ev.LastDNS = &t
	}
	v := apiVerdict{Evidence: ev, Reasons: []string{}}
	if lastSigMin >= 0 {
		t := time.Unix(lastSigMin*60, 0)
		v.LastSignificantAt = &t
	}

	phone := devKind == "phone"
	laptop := devKind == "laptop"
	bgOnly := isBackgroundOnly(cats)
	hedgeApple := func() {
		if bgOnly {
			v.Reasons = append(v.Reasons, "только apple — Apple Music или iCloud, не доказуемо как фон")
		}
	}

	switch {
	case total == 0:
		v.Status = "silent"
		if loggerOK {
			v.Confidence = "high"
			v.Reasons = append(v.Reasons, "0 байт за окно, логгер исправен")
		} else {
			v.Confidence = "low"
			v.Reasons = append(v.Reasons, "0 байт, но здоровье логгера не подтверждено — тишина недоказуема")
		}
	case minOver1MB >= 2:
		v.Status = "active"
		v.Confidence = boolPick(phone, "high", "medium")
		v.Reasons = append(v.Reasons, fmt.Sprintf("%d мин >1 МБ — устойчивый поток", minOver1MB))
		if fresh {
			v.Reasons = append(v.Reasons, "свежий TLS/DNS <3 мин")
		}
		if laptop {
			v.Reasons = append(v.Reasons, "ноутбук — оценка мягче")
		}
		hedgeApple()
	case total >= 20*mb:
		v.Status = "active"
		v.Confidence = boolPick(phone, "high", "medium")
		v.Reasons = append(v.Reasons, "десятки МБ за окно")
		if laptop {
			v.Reasons = append(v.Reasons, "ноутбук — оценка мягче")
		}
		hedgeApple()
	case fresh && !bgOnly:
		v.Status = "active"
		v.Confidence = boolPick(phone, "medium", "low")
		v.Reasons = append(v.Reasons, "свежий TLS/DNS <3 мин к не-фоновой категории")
		if laptop {
			v.Reasons = append(v.Reasons, "ноутбук — мог быть фоновый процесс")
		}
	case bgOnly:
		v.Status = "likely-background"
		v.Confidence = boolPick(laptop, "high", "medium")
		v.Reasons = append(v.Reasons, "только apple/dns, без свежих соединений — вероятно фон (push/OCSP)")
	default:
		v.Status = "likely-background"
		v.Confidence = "low"
		v.Reasons = append(v.Reasons, fmt.Sprintf("малый объём, %d мин >100 КБ, нет устойчивого потока", minOver100KB))
	}
	return v
}

func boolPick(cond bool, ifTrue, ifFalse string) string {
	if cond {
		return ifTrue
	}
	return ifFalse
}

func (s *webServer) handleSystem(w http.ResponseWriter, r *http.Request) {
	var st RuntimeStats
	if b, err := os.ReadFile(filepath.Join(s.logDir, "stats.json")); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	writeJSON(w, map[string]any{
		"stats": st,
		"config": map[string]any{
			"interface": s.iface,
			"wg_config": s.wgConfig,
			"log_dir":   s.logDir,
			"rollup":    s.rollupPath,
		},
	})
}

type tPoint struct {
	T    int64  `json:"t"`
	Down uint64 `json:"down"`
	Up   uint64 `json:"up"`
}

func (s *webServer) handleThroughput(w http.ResponseWriter, r *http.Request) {
	d := parseSince(r, 15*time.Minute)
	now := time.Now()
	series := s.throughputSeries(now.Add(-d), now)
	writeJSON(w, map[string]any{"since": d.String(), "points": series})
}

func (s *webServer) throughputSeries(cutoff, now time.Time) []tPoint {
	per := map[int64]*tPoint{}
	db, err := bolt.Open(s.rollupPath, 0444, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		return zeroThroughputSeries(cutoff, now, per)
	}
	defer db.Close()
	cutoffMinute := cutoff.Unix() / 60
	_ = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(rollupClientBucket)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		start := []byte(fmt.Sprintf("%012d", cutoffMinute))
		for k, v := c.Seek(start); k != nil; k, v = c.Next() {
			parts := strings.SplitN(string(k), "\t", 2)
			if len(parts) != 2 {
				continue
			}
			m, err := strconv.ParseInt(parts[0], 10, 64)
			if err != nil || m < cutoffMinute {
				continue
			}
			tot := decodeRollupTotalValue(v)
			p := per[m]
			if p == nil {
				p = &tPoint{T: m * 60}
				per[m] = p
			}
			p.Down += tot.DownloadBytes
			p.Up += tot.UploadBytes
		}
		return nil
	})
	return zeroThroughputSeries(cutoff, now, per)
}

func zeroThroughputSeries(cutoff, now time.Time, per map[int64]*tPoint) []tPoint {
	startMinute := cutoff.Unix() / 60
	endMinute := now.Unix() / 60
	if endMinute < startMinute {
		return []tPoint{}
	}
	out := make([]tPoint, 0, endMinute-startMinute+1)
	for m := startMinute; m <= endMinute; m++ {
		if p := per[m]; p != nil {
			out = append(out, *p)
		} else {
			out = append(out, tPoint{T: m * 60})
		}
	}
	return out
}

func (s *webServer) handleClients(w http.ResponseWriter, r *http.Request) {
	d := parseSince(r, 15*time.Minute)
	now := time.Now()
	cutoff := now.Add(-d)
	startMinute := cutoff.Unix() / 60
	loggerOK := s.loggerHealthy()
	// Read totals + cats + per-minute series straight from the binary buckets
	// (the same fast path as the snapshot) instead of the heavy flow_minute_v1
	// JSON scan — the board never used the per-target detail that scan produced.
	snaps := s.snapshotFromRollup(cutoff, now)
	// Surface configured-but-silent devices so the board shows who's offline, not
	// just who had traffic (the roster comes from clients.yaml).
	for _, dev := range s.aliases.Roster() {
		if snaps[dev] == nil {
			snaps[dev] = &snapClient{cats: map[string]uint64{}}
		}
	}
	sites, lastTLS := s.lastSitesByClient(cutoff)
	lastDNS := s.lastDNSByClient(cutoff)
	clients := make([]*apiClient, 0, len(snaps))
	for name, sc := range snaps {
		cats := mapToShares(sc.cats)
		c := &apiClient{
			Name:        name,
			Down:        sc.down,
			Up:          sc.up,
			Total:       sc.down + sc.up,
			Cats:        cats,
			Series:      sc.series,
			CurrentSite: sites[name],
			DeviceKind:  s.resolveDeviceKind(name),
			Person:      s.aliases.Person(name),
		}
		if len(cats) > 0 {
			c.TopCategory = cats[0].Category
		}
		v := classify(sc.series, startMinute, c.Total, cats, c.DeviceKind, lastTLS[name], lastDNS[name], now, loggerOK)
		c.Verdict = &v
		clients = append(clients, c)
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].Total > clients[j].Total })
	writeJSON(w, map[string]any{"since": d.String(), "logger_ok": loggerOK, "clients": clients})
}

type apiSnapshotClient struct {
	Name            string        `json:"name"`
	Person          string        `json:"person"`
	DeviceKind      string        `json:"device_kind"`
	Down            uint64        `json:"down"`
	Up              uint64        `json:"up"`
	Total           uint64        `json:"total"`
	MinutesOver100K int           `json:"minutes_over_100k"`
	MinutesOver1MB  int           `json:"minutes_over_1mb"`
	Cats            []apiCatShare `json:"cats"`
	RecentSites     []string      `json:"recent_sites"`
	LastTLS         *time.Time    `json:"last_tls,omitempty"`
	LastDNS         *time.Time    `json:"last_dns,omitempty"`
	Verdict         apiVerdict    `json:"verdict"`
}

// handleSnapshot is the fast path behind the Срез drawer: it reads only the
// compact binary buckets (flow_client_minute_v1 + flow_client_category_minute_v1)
// and the recent-sites tail scan, deliberately skipping the heavy per-target
// flow_minute_v1 JSON aggregation so it stays well under the 300ms burst budget.
// ?clients=a,b ensures an entry (0-byte → silent) for known-but-quiet devices so
// the Срез can name a silent person, not just whoever happened to have traffic.
func (s *webServer) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	d := parseSince(r, 5*time.Minute)
	now := time.Now()
	cutoff := now.Add(-d)
	startMinute := cutoff.Unix() / 60
	loggerOK := s.loggerHealthy()

	snaps := s.snapshotFromRollup(cutoff, now)
	sites, lastTLS := s.recentSitesByClient(cutoff, 4)
	lastDNS := s.lastDNSByClient(cutoff)

	want := map[string]bool{}
	if cl := r.URL.Query().Get("clients"); cl != "" {
		for _, n := range strings.Split(cl, ",") {
			if n = strings.TrimSpace(n); n != "" {
				want[n] = true
				if snaps[n] == nil {
					snaps[n] = &snapClient{cats: map[string]uint64{}}
				}
			}
		}
	}

	out := make([]apiSnapshotClient, 0, len(snaps))
	for name, sc := range snaps {
		if len(want) > 0 && !want[name] {
			continue
		}
		cats := mapToShares(sc.cats)
		devKind := s.resolveDeviceKind(name)
		total := sc.down + sc.up
		v := classify(sc.series, startMinute, total, cats, devKind, lastTLS[name], lastDNS[name], now, loggerOK)
		entry := apiSnapshotClient{
			Name: name, Person: s.aliases.Person(name), DeviceKind: devKind,
			Down: sc.down, Up: sc.up, Total: total,
			MinutesOver100K: sc.minOver100k, MinutesOver1MB: sc.minOver1mb,
			Cats: cats, RecentSites: sites[name], Verdict: v,
		}
		if t := lastTLS[name]; !t.IsZero() {
			entry.LastTLS = &t
		}
		if t := lastDNS[name]; !t.IsZero() {
			entry.LastDNS = &t
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Total > out[j].Total })
	writeJSON(w, map[string]any{
		"since":        d.String(),
		"generated_at": now.Unix(),
		"logger_ok":    loggerOK,
		"clients":      out,
	})
}

type snapClient struct {
	series                  []uint64
	down, up                uint64
	minOver100k, minOver1mb int
	cats                    map[string]uint64
}

// snapshotFromRollup reads per-client minute totals (zero-filled series + down/up
// + >100KB/>1MB minute counts) and per-client category sums straight from the
// binary buckets — one bbolt open, no JSON-target scan.
func (s *webServer) snapshotFromRollup(cutoff, now time.Time) map[string]*snapClient {
	res := map[string]*snapClient{}
	startMin := cutoff.Unix() / 60
	endMin := now.Unix() / 60
	n := int(endMin - startMin + 1)
	if n <= 0 {
		return res
	}
	db, err := bolt.Open(s.rollupPath, 0444, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		return res
	}
	defer db.Close()
	const kb, mb = 1 << 10, 1 << 20
	_ = db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(rollupClientBucket); b != nil {
			c := b.Cursor()
			start := []byte(fmt.Sprintf("%012d", startMin))
			for k, v := c.Seek(start); k != nil; k, v = c.Next() {
				parts := strings.SplitN(string(k), "\t", 2)
				if len(parts) != 2 {
					continue
				}
				m, err := strconv.ParseInt(parts[0], 10, 64)
				if err != nil || m < startMin {
					continue
				}
				idx := int(m - startMin)
				if idx < 0 || idx >= n {
					continue
				}
				sc := res[parts[1]]
				if sc == nil {
					sc = &snapClient{series: make([]uint64, n), cats: map[string]uint64{}}
					res[parts[1]] = sc
				}
				tot := decodeRollupTotalValue(v)
				sc.series[idx] += tot.DownloadBytes + tot.UploadBytes
				sc.down += tot.DownloadBytes
				sc.up += tot.UploadBytes
			}
		}
		// category sums, seeked per client by prefix so we only touch recent minutes
		if cb := tx.Bucket(rollupClientCategoryBucket); cb != nil {
			for name, sc := range res {
				prefix := []byte(name + "\t")
				start := []byte(fmt.Sprintf("%s\t%012d", name, startMin))
				c := cb.Cursor()
				for k, v := c.Seek(start); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
					p := strings.SplitN(string(k), "\t", 3)
					if len(p) != 3 {
						continue
					}
					m, err := strconv.ParseInt(p[1], 10, 64)
					if err != nil || m < startMin {
						continue
					}
					tot := decodeRollupTotalValue(v)
					sc.cats[p[2]] += tot.DownloadBytes + tot.UploadBytes
				}
			}
		}
		return nil
	})
	for _, sc := range res {
		for _, b := range sc.series {
			if b > 100*kb {
				sc.minOver100k++
			}
			if b > mb {
				sc.minOver1mb++
			}
		}
	}
	return res
}

// recentSitesByClient collects up to limit distinct recent SNIs per client
// (newest first) plus the last TLS time, from one tls.jsonl tail scan.
func (s *webServer) recentSitesByClient(cutoff time.Time, limit int) (map[string][]string, map[string]time.Time) {
	sites := map[string][]string{}
	seen := map[string]map[string]bool{}
	last := map[string]time.Time{}
	_ = eachLineReverse(filepath.Join(s.logDir, "tls.jsonl"), func(line []byte) bool {
		var rec TLSRecord
		if json.Unmarshal(line, &rec) != nil {
			return true
		}
		if rec.TS.Before(cutoff) {
			return false
		}
		if _, ok := last[rec.Client]; !ok {
			last[rec.Client] = rec.TS
		}
		if rec.ServerName == "" {
			return true
		}
		if seen[rec.Client] == nil {
			seen[rec.Client] = map[string]bool{}
		}
		if seen[rec.Client][rec.ServerName] || len(sites[rec.Client]) >= limit {
			return true
		}
		seen[rec.Client][rec.ServerName] = true
		sites[rec.Client] = append(sites[rec.Client], rec.ServerName)
		return true
	})
	return sites, last
}

// lastSitesByClient reverse-scans tls.jsonl within the window and returns, per
// client, the most recent SNI plus its timestamp (the timestamp feeds the
// classifier's "fresh TLS" signal — nearly free since we already walk the file).
func (s *webServer) lastSitesByClient(cutoff time.Time) (map[string]string, map[string]time.Time) {
	res := map[string]string{}
	last := map[string]time.Time{}
	_ = eachLineReverse(filepath.Join(s.logDir, "tls.jsonl"), func(line []byte) bool {
		var rec TLSRecord
		if json.Unmarshal(line, &rec) != nil {
			return true
		}
		if rec.TS.Before(cutoff) {
			return false
		}
		if _, ok := last[rec.Client]; !ok {
			last[rec.Client] = rec.TS
		}
		if _, ok := res[rec.Client]; !ok && rec.ServerName != "" {
			res[rec.Client] = rec.ServerName
		}
		return true
	})
	return res, last
}

// lastDNSByClient reverse-scans dns.jsonl within the window for each client's
// most recent query time — the second half of the classifier's freshness signal.
func (s *webServer) lastDNSByClient(cutoff time.Time) map[string]time.Time {
	last := map[string]time.Time{}
	_ = eachLineReverse(filepath.Join(s.logDir, "dns.jsonl"), func(line []byte) bool {
		var rec DNSRecord
		if json.Unmarshal(line, &rec) != nil {
			return true
		}
		if rec.TS.Before(cutoff) {
			return false
		}
		if _, ok := last[rec.Client]; !ok {
			last[rec.Client] = rec.TS
		}
		return true
	})
	return last
}

// loggerHealthy reports whether the capture's stats.json heartbeat is fresh, so
// the classifier can gate SILENT on it (an outage must never read as quiet).
// Mirrors the frontend's 90s staleness threshold.
func (s *webServer) loggerHealthy() bool {
	b, err := os.ReadFile(filepath.Join(s.logDir, "stats.json"))
	if err != nil {
		return false
	}
	var st RuntimeStats
	if json.Unmarshal(b, &st) != nil || st.UpdatedAt.IsZero() {
		return false
	}
	return time.Since(st.UpdatedAt) < 90*time.Second
}

// seriesByClient returns a zero-filled per-minute byte total (download+upload)
// for every client over [cutoff, now], for rendering per-client sparklines.
func (s *webServer) seriesByClient(cutoff, now time.Time) map[string][]uint64 {
	res := map[string][]uint64{}
	startMin := cutoff.Unix() / 60
	endMin := now.Unix() / 60
	n := int(endMin - startMin + 1)
	if n <= 0 {
		return res
	}
	db, err := bolt.Open(s.rollupPath, 0444, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		return res
	}
	defer db.Close()
	_ = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(rollupClientBucket)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		start := []byte(fmt.Sprintf("%012d", startMin))
		for k, v := c.Seek(start); k != nil; k, v = c.Next() {
			parts := strings.SplitN(string(k), "\t", 2)
			if len(parts) != 2 {
				continue
			}
			m, err := strconv.ParseInt(parts[0], 10, 64)
			if err != nil || m < startMin {
				continue
			}
			idx := int(m - startMin)
			if idx < 0 || idx >= n {
				continue
			}
			arr := res[parts[1]]
			if arr == nil {
				arr = make([]uint64, n)
				res[parts[1]] = arr
			}
			tot := decodeRollupTotalValue(v)
			arr[idx] += tot.DownloadBytes + tot.UploadBytes
		}
		return nil
	})
	return res
}

type apiHour struct {
	Hour  int               `json:"hour"`
	Cats  map[string]uint64 `json:"cats"`
	Total uint64            `json:"total"`
}

func (s *webServer) handleClientDetail(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/clients/")
	if rest == "" {
		http.NotFound(w, r)
		return
	}
	name, sub, _ := strings.Cut(rest, "/")
	if sub == "minute" {
		s.handleClientMinute(w, r, name)
		return
	}
	from, to := windowFromRequest(r, 15*time.Minute)
	recentLookback := to.Sub(from)
	if recentLookback < 6*time.Hour {
		recentLookback = 6 * time.Hour
	}
	recentCutoff := to.Add(-recentLookback)
	aggList := s.clientFlowsWindow(name, from, to)
	var down, up uint64
	cat := map[string]uint64{}
	targets := make([]apiFlow, 0, len(aggList))
	for _, a := range aggList {
		down += a.Down
		up += a.Up
		cat[a.Category] += a.Down + a.Up
		targets = append(targets, newAPIFlow(a))
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Total > targets[j].Total })
	if len(targets) > 20 {
		targets = targets[:20]
	}
	recentDNS := s.recentDNSForClient(name, recentCutoff, to, 12)
	recentTLS := s.recentTLSForClient(name, recentCutoff, to, 12)
	series := s.seriesByClient(from, to)[name]
	cats := mapToShares(cat)
	loggerOK := s.loggerHealthy()
	devKind := s.resolveDeviceKind(name)
	// Reuse the recent lists (newest first) for freshness — reaches back further
	// than the window, so "last seen" survives a short window.
	var lastTLS, lastDNS time.Time
	if len(recentTLS) > 0 {
		lastTLS = recentTLS[0].TS
	}
	if len(recentDNS) > 0 {
		lastDNS = recentDNS[0].TS
	}
	verdict := classify(series, from.Unix()/60, down+up, cats, devKind, lastTLS, lastDNS, to, loggerOK)
	writeJSON(w, map[string]any{
		"name":   name,
		"since":  to.Sub(from).Round(time.Minute).String(),
		"from":   from.Unix(),
		"to":     to.Unix(),
		"down":   down,
		"up":     up,
		"total":  down + up,
		"series": series,
		// First minute the zero-filled series covers, so the client can build a
		// throughput x-axis from real server timestamps instead of its own clock.
		"series_start_minute": from.Unix() / 60,
		"categories":          cats,
		"top_targets":         targets,
		// Per-minute reconstruction ribbon (binary bucket; nil for windows too wide
		// to render minute-by-minute). Domains load lazily via /minute.
		"minutes":     s.clientMinuteRibbon(name, from, to),
		"recent_dns":  recentDNS,
		"recent_tls":  recentTLS,
		"day":         s.clientDayTimeline(name),
		"device_kind": devKind,
		"person":      s.aliases.Person(name),
		"logger_ok":   loggerOK,
		"verdict":     verdict,
	})
}

// clientFlowsWindow aggregates one client's per-target flows over [from, to] from
// flow_minute_v1, bounded on both ends (so an explicit ?to= is honored).
func (s *webServer) clientFlowsWindow(name string, from, to time.Time) []*TopAgg {
	fromMin := from.Unix() / 60
	toMin := to.Unix() / 60
	aggs := map[string]*TopAgg{}
	db, err := bolt.Open(s.rollupPath, 0444, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		return nil
	}
	defer db.Close()
	_ = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(rollupBucket)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		start := []byte(fmt.Sprintf("%012d", fromMin))
		for k, v := c.Seek(start); k != nil; k, v = c.Next() {
			var row RollupRow
			if json.Unmarshal(v, &row) != nil {
				continue
			}
			if row.Minute > toMin {
				break
			}
			if row.Minute < fromMin || row.Client != name {
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
		}
		return nil
	})
	out := make([]*TopAgg, 0, len(aggs))
	for _, a := range aggs {
		out = append(out, a)
	}
	return out
}

type apiMinute struct {
	T           int64  `json:"t"` // unix seconds at the minute start
	Bytes       uint64 `json:"bytes"`
	Down        uint64 `json:"down"`
	Up          uint64 `json:"up"`
	TopCategory string `json:"top_category"`
	Over100K    bool   `json:"over_100k"`
	Over1M      bool   `json:"over_1m"`
}

// clientMinuteRibbon returns one zero-filled row per MSK minute over [from, to]
// (silent minutes included) with the dominant category — bytes/flags from the
// binary buckets only, no domain join. Capped so it can't be asked to render an
// unbounded ribbon; nil means "window too wide, don't show the ribbon".
func (s *webServer) clientMinuteRibbon(name string, from, to time.Time) []apiMinute {
	const maxMinutes = 45
	fromMin := from.Unix() / 60
	toMin := to.Unix() / 60
	n := int(toMin - fromMin + 1)
	if n <= 0 || n > maxMinutes {
		return nil
	}
	const kb, mb = 1 << 10, 1 << 20
	out := make([]apiMinute, n)
	cats := make([]map[string]uint64, n)
	for i := range out {
		out[i].T = (fromMin + int64(i)) * 60
	}
	db, err := bolt.Open(s.rollupPath, 0444, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		return out
	}
	defer db.Close()
	_ = db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(rollupClientBucket); b != nil {
			c := b.Cursor()
			start := []byte(fmt.Sprintf("%012d", fromMin))
			for k, v := c.Seek(start); k != nil; k, v = c.Next() {
				parts := strings.SplitN(string(k), "\t", 2)
				if len(parts) != 2 {
					continue
				}
				m, err := strconv.ParseInt(parts[0], 10, 64)
				if err != nil {
					continue
				}
				if m > toMin {
					break
				}
				if m < fromMin || parts[1] != name {
					continue
				}
				tot := decodeRollupTotalValue(v)
				idx := int(m - fromMin)
				out[idx].Down += tot.DownloadBytes
				out[idx].Up += tot.UploadBytes
				out[idx].Bytes += tot.DownloadBytes + tot.UploadBytes
			}
		}
		if cb := tx.Bucket(rollupClientCategoryBucket); cb != nil {
			prefix := []byte(name + "\t")
			start := []byte(fmt.Sprintf("%s\t%012d", name, fromMin))
			c := cb.Cursor()
			for k, v := c.Seek(start); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
				p := strings.SplitN(string(k), "\t", 3)
				if len(p) != 3 {
					continue
				}
				m, err := strconv.ParseInt(p[1], 10, 64)
				if err != nil {
					continue
				}
				if m > toMin {
					break
				}
				if m < fromMin {
					continue
				}
				idx := int(m - fromMin)
				if cats[idx] == nil {
					cats[idx] = map[string]uint64{}
				}
				tot := decodeRollupTotalValue(v)
				cats[idx][p[2]] += tot.DownloadBytes + tot.UploadBytes
			}
		}
		return nil
	})
	for i := range out {
		if cats[i] != nil {
			out[i].TopCategory = topKey(cats[i])
		}
		out[i].Over100K = out[i].Bytes > 100*kb
		out[i].Over1M = out[i].Bytes > mb
	}
	return out
}

// handleClientMinute serves the lazily-loaded domains for a single flagged minute:
// the distinct TLS SNIs and DNS queries in [at, at+60s). Reaches only as far back
// as un-rotated JSONL — older minutes return empty (honestly, not faked).
func (s *webServer) handleClientMinute(w http.ResponseWriter, r *http.Request, name string) {
	at, ok := parseTimeParam(r.URL.Query().Get("at"))
	if !ok {
		http.Error(w, "missing at", http.StatusBadRequest)
		return
	}
	end := at.Add(time.Minute)
	tls := []string{}
	tlsSeen := map[string]bool{}
	_ = eachLineReverse(filepath.Join(s.logDir, "tls.jsonl"), func(line []byte) bool {
		var rec TLSRecord
		if json.Unmarshal(line, &rec) != nil {
			return true
		}
		if rec.TS.Before(at) {
			return false
		}
		if rec.Client != name || rec.ServerName == "" || !rec.TS.Before(end) {
			return true
		}
		if !tlsSeen[rec.ServerName] {
			tlsSeen[rec.ServerName] = true
			tls = append(tls, rec.ServerName)
		}
		return true
	})
	dns := []string{}
	dnsSeen := map[string]bool{}
	_ = eachLineReverse(filepath.Join(s.logDir, "dns.jsonl"), func(line []byte) bool {
		var rec DNSRecord
		if json.Unmarshal(line, &rec) != nil {
			return true
		}
		if rec.TS.Before(at) {
			return false
		}
		if rec.Client != name || rec.Query == "" || !rec.TS.Before(end) {
			return true
		}
		if !dnsSeen[rec.Query] {
			dnsSeen[rec.Query] = true
			dns = append(dns, rec.Query)
		}
		return true
	})
	writeJSON(w, map[string]any{"at": at.Unix(), "tls": tls, "dns": dns})
}

func (s *webServer) recentDNSForClient(name string, cutoff, to time.Time, limit int) []DNSRecord {
	out := []DNSRecord{}
	_ = eachLineReverse(filepath.Join(s.logDir, "dns.jsonl"), func(line []byte) bool {
		var rec DNSRecord
		if json.Unmarshal(line, &rec) != nil {
			return true
		}
		if rec.TS.After(to) {
			return true
		}
		if rec.TS.Before(cutoff) {
			return false
		}
		if rec.Client == name {
			out = append(out, rec)
			if len(out) >= limit {
				return false
			}
		}
		return true
	})
	return out
}

func (s *webServer) recentTLSForClient(name string, cutoff, to time.Time, limit int) []TLSRecord {
	out := []TLSRecord{}
	_ = eachLineReverse(filepath.Join(s.logDir, "tls.jsonl"), func(line []byte) bool {
		var rec TLSRecord
		if json.Unmarshal(line, &rec) != nil {
			return true
		}
		if rec.TS.After(to) {
			return true
		}
		if rec.TS.Before(cutoff) {
			return false
		}
		if rec.Client == name {
			out = append(out, rec)
			if len(out) >= limit {
				return false
			}
		}
		return true
	})
	return out
}

func (s *webServer) clientDayTimeline(name string) []apiHour {
	buckets := make([]apiHour, 24)
	for i := range buckets {
		buckets[i] = apiHour{Hour: i, Cats: map[string]uint64{}}
	}
	if ok := s.clientDayTimelineFromIndex(name, buckets); ok {
		return buckets
	}
	db, err := bolt.Open(s.rollupPath, 0444, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		return buckets
	}
	defer db.Close()
	cutoffMinute := time.Now().Add(-24*time.Hour).Unix() / 60
	_ = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(rollupBucket)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		start := []byte(fmt.Sprintf("%012d", cutoffMinute))
		for k, v := c.Seek(start); k != nil; k, v = c.Next() {
			var row RollupRow
			if json.Unmarshal(v, &row) != nil {
				continue
			}
			if row.Minute < cutoffMinute || row.Client != name {
				continue
			}
			h := mskHour(row.Minute)
			bt := row.DownloadBytes + row.UploadBytes
			buckets[h].Cats[row.Category] += bt
			buckets[h].Total += bt
		}
		return nil
	})
	return buckets
}

func (s *webServer) clientDayTimelineFromIndex(name string, buckets []apiHour) bool {
	db, err := bolt.Open(s.rollupPath, 0444, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		return false
	}
	defer db.Close()
	cutoffMinute := time.Now().Add(-24*time.Hour).Unix() / 60
	foundBucket := false
	_ = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(rollupClientCategoryBucket)
		if b == nil {
			return nil
		}
		foundBucket = true
		prefix := []byte(name + "\t")
		start := []byte(fmt.Sprintf("%s\t%012d", name, cutoffMinute))
		c := b.Cursor()
		for k, v := c.Seek(start); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			parts := strings.SplitN(string(k), "\t", 3)
			if len(parts) != 3 {
				continue
			}
			minute, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil || minute < cutoffMinute {
				continue
			}
			total := decodeRollupTotalValue(v)
			h := mskHour(minute)
			bt := total.DownloadBytes + total.UploadBytes
			buckets[h].Cats[parts[2]] += bt
			buckets[h].Total += bt
		}
		return nil
	})
	return foundBucket
}

func (s *webServer) handleTraffic(w http.ResponseWriter, r *http.Request) {
	d := parseSince(r, 15*time.Minute)
	cutoff := time.Now().Add(-d)
	q := r.URL.Query()
	clientFilter := q.Get("client")
	catFilter := q.Get("category")
	protoFilter := q.Get("proto")
	search := strings.ToLower(q.Get("q"))
	limit := atoiDefault(q.Get("limit"), 50)
	aggs := map[string]*TopAgg{}
	aggregateFromRollup(s.rollupPath, cutoff, clientFilter, aggs)
	rows := make([]apiFlow, 0, len(aggs))
	for _, a := range aggs {
		if catFilter != "" && catFilter != "all" && a.Category != catFilter {
			continue
		}
		if protoFilter != "" && protoFilter != "all" && a.Proto != protoFilter {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(a.Target), search) {
			continue
		}
		rows = append(rows, newAPIFlow(a))
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Total > rows[j].Total })
	total := len(rows)
	if limit > 0 && limit < len(rows) {
		rows = rows[:limit]
	}
	writeJSON(w, map[string]any{"since": d.String(), "total": total, "rows": rows})
}

type apiCategory struct {
	Category  string `json:"category"`
	Down      uint64 `json:"down"`
	Up        uint64 `json:"up"`
	Total     uint64 `json:"total"`
	TopClient string `json:"top_client"`
	TopTarget string `json:"top_target"`
}

func (s *webServer) handleCategories(w http.ResponseWriter, r *http.Request) {
	d := parseSince(r, 15*time.Minute)
	cutoff := time.Now().Add(-d)
	aggs := map[string]*TopAgg{}
	aggregateFromRollup(s.rollupPath, cutoff, "", aggs)
	type acc struct {
		down, up uint64
		clients  map[string]uint64
		targets  map[string]uint64
	}
	m := map[string]*acc{}
	for _, a := range aggs {
		x := m[a.Category]
		if x == nil {
			x = &acc{clients: map[string]uint64{}, targets: map[string]uint64{}}
			m[a.Category] = x
		}
		x.down += a.Down
		x.up += a.Up
		x.clients[a.Client] += a.Down + a.Up
		x.targets[a.Target] += a.Down + a.Up
	}
	out := make([]apiCategory, 0, len(m))
	for cat, x := range m {
		out = append(out, apiCategory{
			Category:  cat,
			Down:      x.down,
			Up:        x.up,
			Total:     x.down + x.up,
			TopClient: topKey(x.clients),
			TopTarget: topKey(x.targets),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Total > out[j].Total })
	writeJSON(w, map[string]any{"since": d.String(), "categories": out})
}

func (s *webServer) handleDNS(w http.ResponseWriter, r *http.Request) {
	d := parseSince(r, 15*time.Minute)
	cutoff := time.Now().Add(-d)
	q := r.URL.Query()
	clientFilter := q.Get("client")
	qtype := q.Get("qtype")
	errorsOnly := q.Get("errors") == "1" || q.Get("errors") == "true"
	search := strings.ToLower(q.Get("q"))
	limit := atoiDefault(q.Get("limit"), 100)
	out := []DNSRecord{}
	errCount := 0
	_ = eachLineReverse(filepath.Join(s.logDir, "dns.jsonl"), func(line []byte) bool {
		var rec DNSRecord
		if json.Unmarshal(line, &rec) != nil {
			return true
		}
		if rec.TS.Before(cutoff) {
			return false
		}
		if rec.RCode != 0 {
			errCount++
		}
		if clientFilter != "" && rec.Client != clientFilter {
			return true
		}
		if qtype != "" && qtype != "all" && rec.QType != qtype {
			return true
		}
		if errorsOnly && rec.RCode == 0 {
			return true
		}
		if search != "" && !strings.Contains(strings.ToLower(rec.Query), search) {
			return true
		}
		out = append(out, rec)
		return true
	})
	if len(out) > limit {
		out = out[:limit]
	}
	writeJSON(w, map[string]any{"since": d.String(), "errors": errCount, "records": out})
}

type apiSite struct {
	Site     string    `json:"site"`
	Category string    `json:"category"`
	Hits     int       `json:"hits"`
	Clients  []string  `json:"clients"`
	Last     time.Time `json:"last"`
}

func (s *webServer) handleTLS(w http.ResponseWriter, r *http.Request) {
	d := parseSince(r, 15*time.Minute)
	cutoff := time.Now().Add(-d)
	q := r.URL.Query()
	clientFilter := q.Get("client")
	search := strings.ToLower(q.Get("q"))
	type sg struct {
		hits    int
		clients map[string]bool
		last    time.Time
		cat     string
	}
	groups := map[string]*sg{}
	recent := []TLSRecord{}
	_ = eachLineReverse(filepath.Join(s.logDir, "tls.jsonl"), func(line []byte) bool {
		var rec TLSRecord
		if json.Unmarshal(line, &rec) != nil {
			return true
		}
		if rec.TS.Before(cutoff) {
			return false
		}
		if clientFilter != "" && rec.Client != clientFilter {
			return true
		}
		if search != "" && !strings.Contains(strings.ToLower(rec.ServerName), search) {
			return true
		}
		g := groups[rec.ServerName]
		if g == nil {
			g = &sg{clients: map[string]bool{}, last: rec.TS, cat: categorize(rec.ServerName, rec.RemoteIP, "tcp", rec.RemotePort)}
			groups[rec.ServerName] = g
		}
		g.hits++
		g.clients[rec.Client] = true
		if rec.TS.After(g.last) {
			g.last = rec.TS
		}
		if len(recent) < 30 {
			recent = append(recent, rec)
		}
		return true
	})
	sites := make([]apiSite, 0, len(groups))
	for name, g := range groups {
		cl := make([]string, 0, len(g.clients))
		for c := range g.clients {
			cl = append(cl, c)
		}
		sort.Strings(cl)
		sites = append(sites, apiSite{Site: name, Category: g.cat, Hits: g.hits, Clients: cl, Last: g.last})
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].Hits > sites[j].Hits })
	writeJSON(w, map[string]any{"since": d.String(), "sites": sites, "recent": recent})
}

type apiReportRow struct {
	Name  string `json:"name"`
	Down  uint64 `json:"down"`
	Up    uint64 `json:"up"`
	Total uint64 `json:"total"`
}

func (s *webServer) handleReport(w http.ResponseWriter, r *http.Request) {
	d := parseSince(r, 24*time.Hour)
	cutoff := time.Now().Add(-d)
	byClient, byCategory, rows, _ := aggregateReportTotalsFromRollup(s.rollupPath, cutoff)
	toRows := func(m map[string]*TopAgg, nameFn func(*TopAgg) string) []apiReportRow {
		out := make([]apiReportRow, 0, len(m))
		for _, a := range m {
			out = append(out, apiReportRow{Name: nameFn(a), Down: a.Down, Up: a.Up, Total: a.Down + a.Up})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Total > out[j].Total })
		return out
	}
	writeJSON(w, map[string]any{
		"since":       d.String(),
		"rollup_rows": rows,
		"by_client":   toRows(byClient, func(a *TopAgg) string { return a.Client }),
		"by_category": toRows(byCategory, func(a *TopAgg) string { return a.Category }),
	})
}

func (s *webServer) handleStatsStream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	send := func() {
		b, err := os.ReadFile(filepath.Join(s.logDir, "stats.json"))
		if err != nil {
			return
		}
		var buf bytes.Buffer
		if json.Compact(&buf, b) != nil {
			return
		}
		_, _ = w.Write([]byte("event: stats\ndata: "))
		_, _ = w.Write(buf.Bytes())
		_, _ = w.Write([]byte("\n\n"))
		fl.Flush()
	}
	ctx := r.Context()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	send()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			send()
		}
	}
}

func eachLineReverse(path string, fn func([]byte) bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	const block = 256 * 1024
	var carry []byte
	for pos := st.Size(); pos > 0; {
		n := int64(block)
		if pos < n {
			n = pos
		}
		pos -= n
		buf := make([]byte, n)
		if _, err := f.ReadAt(buf, pos); err != nil && err != io.EOF {
			return err
		}
		buf = append(buf, carry...)
		lines := strings.Split(string(buf), "\n")
		if pos > 0 {
			carry = []byte(lines[0])
			lines = lines[1:]
		} else {
			carry = nil
		}
		for i := len(lines) - 1; i >= 0; i-- {
			line := strings.TrimSpace(lines[i])
			if line == "" {
				continue
			}
			if !fn([]byte(line)) {
				return nil
			}
		}
	}
	return nil
}
