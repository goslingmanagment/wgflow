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

type webServer struct {
	logDir     string
	rollupPath string
	wgConfig   string
	iface      string
}

func webCmd(args []string) error {
	fset := flag.NewFlagSet("web", flag.ExitOnError)
	listen := fset.String("listen", ":8080", "listen address")
	logDir := fset.String("log-dir", "/var/log/wgflow", "log directory")
	rollupPath := fset.String("rollup", "/var/lib/wgflow/rollup.db", "rollup DB path")
	wgConfig := fset.String("wg-config", "/etc/wireguard/wg0.conf", "WireGuard config path")
	iface := fset.String("iface", "wg0", "interface label")
	authPassword := fset.String("auth-password", os.Getenv("WGFLOW_WEB_PASSWORD"), "HTTP Basic Auth password; defaults to WGFLOW_WEB_PASSWORD")
	authRealm := fset.String("auth-realm", "wgflow", "HTTP Basic Auth realm")
	if err := fset.Parse(args); err != nil {
		return err
	}
	s := &webServer{logDir: *logDir, rollupPath: *rollupPath, wgConfig: *wgConfig, iface: *iface}
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
}

type apiClient struct {
	Name        string        `json:"name"`
	Down        uint64        `json:"down"`
	Up          uint64        `json:"up"`
	Total       uint64        `json:"total"`
	TopCategory string        `json:"top_category"`
	TopTarget   string        `json:"top_target"`
	CurrentSite string        `json:"current_site"`
	Series      []uint64      `json:"series"`
	Cats        []apiCatShare `json:"cats"`
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
	clients := s.aggregateClients(cutoff)
	sites := s.lastSitesByClient(cutoff)
	series := s.seriesByClient(cutoff, now)
	for _, c := range clients {
		c.CurrentSite = sites[c.Name]
		c.Series = series[c.Name]
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].Total > clients[j].Total })
	writeJSON(w, map[string]any{"since": d.String(), "clients": clients})
}

func (s *webServer) aggregateClients(cutoff time.Time) []*apiClient {
	aggs := map[string]*TopAgg{}
	aggregateFromRollup(s.rollupPath, cutoff, "", aggs)
	byClient := map[string]*apiClient{}
	cats := map[string]map[string]uint64{}
	topTargetBytes := map[string]uint64{}
	for _, a := range aggs {
		c := byClient[a.Client]
		if c == nil {
			c = &apiClient{Name: a.Client}
			byClient[a.Client] = c
			cats[a.Client] = map[string]uint64{}
		}
		c.Down += a.Down
		c.Up += a.Up
		tb := a.Down + a.Up
		cats[a.Client][a.Category] += tb
		if tb > topTargetBytes[a.Client] {
			topTargetBytes[a.Client] = tb
			c.TopTarget = a.Target
		}
	}
	out := make([]*apiClient, 0, len(byClient))
	for name, c := range byClient {
		c.Total = c.Down + c.Up
		c.Cats = mapToShares(cats[name])
		if len(c.Cats) > 0 {
			c.TopCategory = c.Cats[0].Category
		}
		out = append(out, c)
	}
	return out
}

func (s *webServer) lastSitesByClient(cutoff time.Time) map[string]string {
	res := map[string]string{}
	_ = eachLineReverse(filepath.Join(s.logDir, "tls.jsonl"), func(line []byte) bool {
		var rec TLSRecord
		if json.Unmarshal(line, &rec) != nil {
			return true
		}
		if rec.TS.Before(cutoff) {
			return false
		}
		if _, ok := res[rec.Client]; !ok && rec.ServerName != "" {
			res[rec.Client] = rec.ServerName
		}
		return true
	})
	return res
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
	name := strings.TrimPrefix(r.URL.Path, "/api/clients/")
	if name == "" {
		http.NotFound(w, r)
		return
	}
	d := parseSince(r, 15*time.Minute)
	now := time.Now()
	cutoff := now.Add(-d)
	recentLookback := d
	if recentLookback < 6*time.Hour {
		recentLookback = 6 * time.Hour
	}
	recentCutoff := now.Add(-recentLookback)
	aggs := map[string]*TopAgg{}
	aggregateFromRollup(s.rollupPath, cutoff, name, aggs)
	var down, up uint64
	cat := map[string]uint64{}
	targets := make([]apiFlow, 0, len(aggs))
	for _, a := range aggs {
		down += a.Down
		up += a.Up
		cat[a.Category] += a.Down + a.Up
		targets = append(targets, apiFlow{Client: a.Client, Category: a.Category, Target: a.Target, Proto: a.Proto, Port: a.Port, Down: a.Down, Up: a.Up, Total: a.Down + a.Up})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Total > targets[j].Total })
	if len(targets) > 20 {
		targets = targets[:20]
	}
	writeJSON(w, map[string]any{
		"name":        name,
		"since":       d.String(),
		"down":        down,
		"up":          up,
		"total":       down + up,
		"series":      s.seriesByClient(cutoff, now)[name],
		"categories":  mapToShares(cat),
		"top_targets": targets,
		"recent_dns":  s.recentDNSForClient(name, recentCutoff, 12),
		"recent_tls":  s.recentTLSForClient(name, recentCutoff, 12),
		"day":         s.clientDayTimeline(name),
	})
}

func (s *webServer) recentDNSForClient(name string, cutoff time.Time, limit int) []DNSRecord {
	out := []DNSRecord{}
	_ = eachLineReverse(filepath.Join(s.logDir, "dns.jsonl"), func(line []byte) bool {
		var rec DNSRecord
		if json.Unmarshal(line, &rec) != nil {
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

func (s *webServer) recentTLSForClient(name string, cutoff time.Time, limit int) []TLSRecord {
	out := []TLSRecord{}
	_ = eachLineReverse(filepath.Join(s.logDir, "tls.jsonl"), func(line []byte) bool {
		var rec TLSRecord
		if json.Unmarshal(line, &rec) != nil {
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
			h := time.Unix(row.Minute*60, 0).Hour()
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
			h := time.Unix(minute*60, 0).Hour()
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
		rows = append(rows, apiFlow{Client: a.Client, Category: a.Category, Target: a.Target, Proto: a.Proto, Port: a.Port, Down: a.Down, Up: a.Up, Total: a.Down + a.Up})
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
