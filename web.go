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
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
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
	return hourInLocation(unixMinute, mskLocation)
}

// hourInLocation maps a unix-minute bucket to its hour-of-day (0–23) in loc.
func hourInLocation(unixMinute int64, loc *time.Location) int {
	return time.Unix(unixMinute*60, 0).In(loc).Hour()
}

// Verdict-engine thresholds, shared with the snapshot/ribbon counters so
// "minutes over X" means the same X everywhere it is computed or displayed.
const (
	// A minute above this is a "real use" trace; below is likely push/keep-alive.
	significantMinuteBytes = 100 << 10
	// A minute above this suggests streaming or downloading.
	heavyMinuteBytes = 1 << 20
	// A window total that alone reads as active use even without heavy minutes.
	activeTotalBytes = 20 << 20
	// This many >1MB minutes count as a sustained stream.
	activeHeavyMinutes = 2
	// How recent a TLS/DNS trace must be to count as "just now".
	freshSignalWindow = 3 * time.Minute
)

const (
	// loggerHeartbeatMax mirrors the frontend's staleness threshold: stats.json
	// older than this means the capture may be down.
	loggerHeartbeatMax = 90 * time.Second
	// Attribution evidence windows: handshakes within strongLookback of the flow
	// window are strong evidence; up to maxLookback they are only a low-priority
	// fallback for CDN connections that outlive their visible handshakes.
	attributionStrongLookback = 2 * time.Hour
	attributionMaxLookback    = 6 * time.Hour
	// How many candidate domains per IP the UI gets to show.
	attributionMaxCandidates = 4
	// Widest window the per-minute ribbon will render; wider windows return nil
	// ("don't show the ribbon") instead of an unbounded row list.
	ribbonMaxMinutes = 45
	// Response-size defaults/caps for the list endpoints.
	trafficDefaultLimit    = 50
	dnsDefaultLimit        = 100
	detailTopTargets       = 20
	detailRecentEvents     = 12
	tlsRecentSample        = 30
	snapshotSitesPerClient = 4
)

type webServer struct {
	logDir     string
	rollupPath string
	wgConfig   string
	iface      string
	aliases    *AliasConfig
	// loc is the -tz day-bucketing zone; nil falls back to MSK (see location).
	loc *time.Location
}

// location returns the day-bucketing time zone. The nil fallback keeps the
// zero-value webServer (tests, embedded use) on the historical MSK behavior.
func (s *webServer) location() *time.Location {
	if s.loc != nil {
		return s.loc
	}
	return mskLocation
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
	asnDBPath := fset.String("asn-db", "", "ASN .mmdb database (db-ip ASN Lite / GeoLite2-ASN) used to name IP owners the builtin table misses (optional)")
	authPassword := fset.String("auth-password", os.Getenv("WGFLOW_WEB_PASSWORD"), "HTTP Basic Auth password; defaults to WGFLOW_WEB_PASSWORD")
	authRealm := fset.String("auth-realm", "wgflow", "HTTP Basic Auth realm")
	allowNoAuth := fset.Bool("allow-no-auth", false, "serve without a password even on a non-loopback address (dangerous: the whole household's traffic becomes public)")
	tzName := fset.String("tz", "Europe/Moscow", "IANA time zone for day bucketing (backend only; the frontend still labels hours in MSK)")
	if err := fset.Parse(args); err != nil {
		return err
	}
	if err := validateWebAuth(*listen, *authPassword, *allowNoAuth); err != nil {
		return err
	}
	if *authPassword == "" {
		// Deliberately loud: running open is a conscious choice (loopback+tunnel
		// is the blessed setup), and the operator should see it in the journal.
		log.Printf("WARNING: no auth password set — anyone who can reach %s sees all traffic history; set WGFLOW_WEB_PASSWORD to protect it", *listen)
	}
	// The default keeps mskLocation's tzdata-less FixedZone fallback; any other
	// zone must resolve or the operator gets garbage hour buckets silently.
	loc := mskLocation
	if *tzName != "Europe/Moscow" {
		l, err := time.LoadLocation(*tzName)
		if err != nil {
			return fmt.Errorf("-tz %q: %w", *tzName, err)
		}
		loc = l
	}
	aliases, err := loadAliasConfig(*clientsConfig)
	if err != nil {
		return fmt.Errorf("clients-config %s: %w", *clientsConfig, err)
	}
	// A missing or broken ASN DB is a warning, not a startup failure: the panel
	// still works, targets just fall back to the builtin prefix table.
	if *asnDBPath != "" {
		if asn, err := openASNDB(*asnDBPath); err != nil {
			log.Printf("WARNING: asn-db %s unusable, continuing without it: %v", *asnDBPath, err)
		} else {
			setIPOrgResolver(asn)
			log.Printf("asn-db=%s loaded", *asnDBPath)
		}
	}
	s := &webServer{logDir: *logDir, rollupPath: *rollupPath, wgConfig: *wgConfig, iface: *iface, aliases: aliases, loc: loc}
	log.Printf("clients-config=%s people=%d devices=%d", *clientsConfig, len(aliases.people), len(aliases.roster))
	mux := http.NewServeMux()
	s.routes(mux)
	handler := http.Handler(mux)
	if *authPassword != "" {
		handler = basicAuthHandler(handler, *authPassword, *authRealm)
	}
	log.Printf("wgflow web listening on %s (log-dir=%s rollup=%s auth=%t)", *listen, *logDir, *rollupPath, *authPassword != "")
	srv := &http.Server{
		Addr:    *listen,
		Handler: handler,
		// Slow-loris protection. No WriteTimeout on purpose: it would kill the
		// long-lived SSE stream at /api/stats/stream.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return srv.ListenAndServe()
}

// validateWebAuth refuses to start a passwordless server on a non-loopback
// address. The default -listen :8080 binds every interface, and the API exposes
// the whole household's browsing history — that must never happen silently.
// Loopback without a password is fine (SSH tunnel is the blessed setup).
func validateWebAuth(listen, password string, allowNoAuth bool) error {
	if password != "" || allowNoAuth || listenIsLoopback(listen) {
		return nil
	}
	return fmt.Errorf("refusing to listen on %q without a password: it would expose all traffic history to the network; set WGFLOW_WEB_PASSWORD (or -auth-password), bind to 127.0.0.1 and tunnel in, or pass --allow-no-auth to serve open anyway", listen)
}

// listenIsLoopback reports whether a listen address can only be reached from
// this host. An empty host (":8080") binds all interfaces — not loopback.
func listenIsLoopback(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		host = listen
	}
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *webServer) routes(mux *http.ServeMux) {
	mux.HandleFunc("/api/system", requireGET(s.handleSystem))
	mux.HandleFunc("/api/throughput", requireGET(s.handleThroughput))
	mux.HandleFunc("/api/clients", requireGET(s.handleClients))
	mux.HandleFunc("/api/clients/", requireGET(s.handleClientDetail))
	mux.HandleFunc("/api/snapshot", requireGET(s.handleSnapshot))
	mux.HandleFunc("/api/traffic", requireGET(s.handleTraffic))
	mux.HandleFunc("/api/categories", requireGET(s.handleCategories))
	mux.HandleFunc("/api/dns", requireGET(s.handleDNS))
	mux.HandleFunc("/api/tls", requireGET(s.handleTLS))
	mux.HandleFunc("/api/report", requireGET(s.handleReport))
	mux.HandleFunc("/api/stats/stream", requireGET(s.handleStatsStream))
	mux.Handle("/", s.staticHandler())
}

// requireGET rejects mutating methods on the read-only API with a proper 405 +
// Allow header instead of letting handlers silently treat POST like GET.
func requireGET(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		h(w, r)
	}
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

// asnDB adapts a MaxMind-format ASN database (db-ip ASN Lite, GeoLite2-ASN)
// to the ipOrgResolver hook consulted after the builtin prefix table. Loaded
// once at startup from -asn-db; lookups are read-only and goroutine-safe.
type asnDB struct {
	reader *maxminddb.Reader
}

func openASNDB(path string) (*asnDB, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &asnDB{reader: r}, nil
}

func (a *asnDB) OrgForIP(addr netip.Addr) string {
	var rec struct {
		Org string `maxminddb:"autonomous_system_organization"`
		ASN uint   `maxminddb:"autonomous_system_number"`
	}
	if err := a.reader.Lookup(net.IP(addr.AsSlice()), &rec); err != nil {
		return ""
	}
	if rec.Org != "" {
		return rec.Org
	}
	if rec.ASN != 0 {
		// A number with no name is still better than an anonymous IP.
		return fmt.Sprintf("AS%d", rec.ASN)
	}
	return ""
}

func (s *webServer) staticHandler() http.Handler {
	dist, err := fs.Sub(webAssets, "webui/dist")
	if err != nil {
		log.Printf("web assets unavailable: %v", err)
	}
	fileServer := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Any /api/ path that reached the catch-all handler matched no API route;
		// answering it with the SPA's HTML and a 200 hides typos from API clients.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSONError(w, http.StatusNotFound, "unknown API path")
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if f, err := dist.Open(p); err == nil {
			st, statErr := f.Stat()
			f.Close()
			if statErr == nil && st.IsDir() {
				// Never autoindex embedded directories (/assets/ listed every bundle).
				http.NotFound(w, r)
				return
			}
			if statErr == nil {
				setStaticCacheHeaders(w, p)
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		b, err := fs.ReadFile(dist, "index.html")
		if err != nil {
			http.Error(w, "ui not built", http.StatusNotFound)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
	})
}

// setStaticCacheHeaders lets browsers cache the content-hashed Vite bundles
// forever while always revalidating the entry point that references them.
func setStaticCacheHeaders(w http.ResponseWriter, p string) {
	if strings.HasPrefix(p, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		return
	}
	if p == "index.html" {
		w.Header().Set("Cache-Control", "no-cache")
	}
}

// writeJSONError is the JSON analog of http.Error for API responses.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// openRollupReadOnly is the single place the web server opens the rollup DB.
// The 5s flock timeout matters: the capture process holds the write lock, and
// hanging a request forever on a wedged DB would be worse than failing it.
func openRollupReadOnly(path string) (*bolt.DB, error) {
	return bolt.Open(path, 0444, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
}

// scanMinuteKeyRange walks a rollup bucket whose keys start with a zero-padded
// minute ("%012d\t<rest>"), calling fn for [fromMin, toMin]. It breaks — not
// skips — once past toMin: the key order makes everything after the bound
// irrelevant, and the copies of this loop used to pay for scanning it anyway.
func scanMinuteKeyRange(tx *bolt.Tx, bucket []byte, fromMin, toMin int64, fn func(minute int64, rest string, v []byte)) {
	b := tx.Bucket(bucket)
	if b == nil {
		return
	}
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
		if m < fromMin {
			continue
		}
		fn(m, parts[1], v)
	}
}

// scanClientCategoryRange walks flow_client_category_minute_v1 for one client
// over [fromMin, toMin], decoding the packed totals. Returns false when the
// bucket does not exist (a DB from before the index was introduced) so callers
// can fall back to the heavy flow_minute_v1 scan.
func scanClientCategoryRange(tx *bolt.Tx, name string, fromMin, toMin int64, fn func(minute int64, category string, tot RollupTotal)) bool {
	b := tx.Bucket(rollupClientCategoryBucket)
	if b == nil {
		return false
	}
	prefix := []byte(name + "\t")
	start := []byte(fmt.Sprintf("%s\t%012d", name, fromMin))
	c := b.Cursor()
	for k, v := c.Seek(start); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
		parts := strings.SplitN(string(k), "\t", 3)
		if len(parts) != 3 {
			continue
		}
		m, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			continue
		}
		if m > toMin {
			break
		}
		if m < fromMin {
			continue
		}
		fn(m, parts[2], decodeRollupTotalValue(v))
	}
	return true
}

// logRateLimited prints at most one message per key per interval. Readers run
// on every dashboard poll, so a broken DB or log file must not flood the
// journal — but it must not be invisible either.
var (
	logRateMu   sync.Mutex
	logRateLast = map[string]time.Time{}
)

func logRateLimited(key, format string, args ...any) {
	const interval = 30 * time.Second
	logRateMu.Lock()
	last, ok := logRateLast[key]
	if ok && time.Since(last) < interval {
		logRateMu.Unlock()
		return
	}
	logRateLast[key] = time.Now()
	logRateMu.Unlock()
	log.Printf(format, args...)
}

// scanLogReverse walks a JSONL log newest-first, surfacing (rate-limited) any
// failure other than the file simply not existing yet. Swallowing these errors
// made an unreadable log indistinguishable from a quiet network.
func scanLogReverse(path string, fn func([]byte) bool) {
	if err := eachLineReverse(path, fn); err != nil && !os.IsNotExist(err) {
		logRateLimited("scan:"+path, "wgflow web: scan %s: %v", path, err)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// maxQueryWindow caps every client-supplied time window. Rollup readers
// allocate one slot per minute of window per client (snapshotFromRollup's
// make([]uint64, minutes)), so an unclamped ?from=1 or ?since=200000h is an
// OOM vector, not just a slow query. 31 days ≈ 45k minutes ≈ 360KB/client.
const maxQueryWindow = 31 * 24 * time.Hour

// maxLimitParam caps ?limit=: the UI never asks for more than a few hundred
// rows, so anything above this is a mistake or abuse.
const maxLimitParam = 1000

func parseSince(r *http.Request, def time.Duration) time.Duration {
	v := r.URL.Query().Get("since")
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return min(d, maxQueryWindow)
}

// atoiDefault parses ?limit=-style knobs; capped so a single request cannot
// demand an unbounded response.
func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return def
	}
	return min(n, maxLimitParam)
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
// The window is clamped to maxQueryWindow (keeping the `to` end, since recent
// data is what the caller actually wants) — see maxQueryWindow for why.
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
	if to.Sub(from) > maxQueryWindow {
		from = to.Add(-maxQueryWindow)
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
	Client                string   `json:"client"`
	Category              string   `json:"category"`
	Target                string   `json:"target"`
	AppTarget             string   `json:"app_target,omitempty"`
	ResolvedTarget        string   `json:"resolved_target,omitempty"`
	TargetOrg             string   `json:"target_org,omitempty"`
	AttributionSource     string   `json:"attribution_source,omitempty"`
	AttributionCandidates []string `json:"attribution_candidates,omitempty"`
	Proto                 string   `json:"proto"`
	Port                  uint16   `json:"port"`
	Down                  uint64   `json:"down"`
	Up                    uint64   `json:"up"`
	Total                 uint64   `json:"total"`
	// IsIP marks a target we could not resolve to a hostname (no SNI, no DNS) —
	// usually QUIC. The UI labels these "no hostname (QUIC)" instead of showing a
	// bare IP that reads like a fabricated or missing domain.
	IsIP bool `json:"is_ip"`
}

func newAPIFlow(a *TopAgg) apiFlow {
	return newAPIFlowWithAttribution(a, nil)
}

// Reverse-DNS warming: enrichTarget's LookupAddr blocks up to 120ms per cache
// miss, and handlers used to call it sequentially inside row loops — a cold
// /api/traffic page could stall for seconds. Handlers now only ever see cache
// hits; misses are queued here and resolved by one background goroutine.
const (
	// How long a request-path placeholder suppresses the blocking lookup while
	// the warmer works. Short, so a dropped warm retries on a later request.
	reverseDNSWarmGrace = 15 * time.Second
	// Pause between background lookups: keeps a burst of unknown IPs from
	// hammering the resolver (each lookup already carries a 120ms timeout).
	reverseDNSWarmPause = 50 * time.Millisecond
)

var (
	reverseDNSWarmOnce     sync.Once
	reverseDNSWarmCh       chan string
	reverseDNSWarmMu       sync.Mutex
	reverseDNSWarmInFlight = map[string]bool{}
)

func queueReverseDNSWarm(ip string) {
	reverseDNSWarmOnce.Do(func() {
		reverseDNSWarmCh = make(chan string, 256)
		go reverseDNSWarmWorker()
	})
	reverseDNSWarmMu.Lock()
	if reverseDNSWarmInFlight[ip] {
		reverseDNSWarmMu.Unlock()
		return
	}
	reverseDNSWarmInFlight[ip] = true
	reverseDNSWarmMu.Unlock()
	select {
	case reverseDNSWarmCh <- ip:
	default:
		// Queue full: drop the warm; the short placeholder grace means a later
		// request simply re-queues it.
		reverseDNSWarmMu.Lock()
		delete(reverseDNSWarmInFlight, ip)
		reverseDNSWarmMu.Unlock()
	}
}

func reverseDNSWarmWorker() {
	for ip := range reverseDNSWarmCh {
		// Delete the placeholder so reverseTargetName performs the real lookup
		// and stores the result with its normal positive/negative TTL.
		reverseDNSDelete(ip)
		reverseTargetName(ip)
		reverseDNSWarmMu.Lock()
		delete(reverseDNSWarmInFlight, ip)
		reverseDNSWarmMu.Unlock()
		time.Sleep(reverseDNSWarmPause)
	}
}

// enrichTargetNonBlocking is enrichTarget for request paths: identical output
// on reverse-DNS cache hits, but on a miss it seeds a short-lived placeholder
// (so the inner LookupAddr is skipped), queues a background warm, and returns
// the static enrichment for now. An expired entry keeps serving its old name
// during the grace period instead of blocking (stale-while-revalidate).
func enrichTargetNonBlocking(target, remoteIP, proto string, port uint16) (resolvedTarget, targetOrg string) {
	ip := target
	if net.ParseIP(ip) == nil {
		ip = remoteIP
	}
	// Mirror the only condition under which enrichTarget consults reverse DNS.
	if net.ParseIP(ip) != nil && proto == "tcp" && port == 443 {
		if r, ok := reverseDNSLookup(ip); !ok {
			reverseDNSStore(ip, reverseDNSResult{expiresAt: time.Now().Add(reverseDNSWarmGrace)})
			queueReverseDNSWarm(ip)
		} else if !time.Now().Before(r.expiresAt) {
			reverseDNSStore(ip, reverseDNSResult{name: r.name, expiresAt: time.Now().Add(reverseDNSWarmGrace)})
			queueReverseDNSWarm(ip)
		}
	}
	return enrichTarget(target, remoteIP, proto, port)
}

func newAPIFlowWithAttribution(a *TopAgg, attrs map[string]apiFlowAttribution) apiFlow {
	resolved, org := enrichTargetNonBlocking(a.Target, "", a.Proto, a.Port)
	isIP := net.ParseIP(a.Target) != nil
	var appTarget, attrSource string
	var attrCandidates []string
	if isIP && attrs != nil {
		if attr := attrs[flowAttributionKey(a.Client, a.Target)]; attr.AppTarget != "" {
			appTarget = attr.AppTarget
			attrSource = attr.Source
			attrCandidates = attr.Candidates
		}
	}
	if !isIP {
		appTarget = a.Target
	}
	targetForCat := a.Target
	if appTarget != "" {
		targetForCat = appTarget
	} else if resolved != "" {
		targetForCat = resolved
	}
	category := a.Category
	if org != "" {
		targetForCat += " " + org
	}
	if better := categorize(targetForCat, a.Target, a.Proto, a.Port); better != "other" && (category == "" || category == "other" || isIP) {
		category = better
	}
	return apiFlow{
		Client: a.Client, Category: category, Target: a.Target, AppTarget: appTarget, ResolvedTarget: resolved, TargetOrg: org,
		AttributionSource: attrSource, AttributionCandidates: attrCandidates, Proto: a.Proto, Port: a.Port,
		Down: a.Down, Up: a.Up, Total: a.Down + a.Up, IsIP: isIP,
	}
}

func apiFlowDisplayTarget(f apiFlow) string {
	if f.AppTarget != "" {
		return f.AppTarget
	}
	if f.ResolvedTarget != "" {
		return f.ResolvedTarget
	}
	return f.Target
}

type apiFlowAttribution struct {
	AppTarget  string
	Source     string
	Candidates []string
}

type attributionCandidate struct {
	Domain   string
	Source   string
	Hits     int
	Priority int
	Last     time.Time
}

func flowAttributionKey(client, ip string) string {
	return client + "\t" + ip
}

// The attribution scan re-reads up to 6 hours of two JSONL files; doing that on
// every /api/traffic, /api/categories and client-detail request is the single
// biggest per-request cost. The rollup generation (stats.json last_flush_at)
// only advances every ~30s, so keying a cache on it gives natural invalidation
// without inventing a TTL ("flush-generation cache", approved in the roadmap).
const attributionCacheMax = 32

type attributionCacheKey struct {
	gen     int64 // stats.json last_flush_at, UnixNano
	fromMin int64
	toMin   int64
	client  string
}

type attributionCacheEntry struct {
	val   map[string]apiFlowAttribution
	added time.Time
}

var (
	attributionCacheMu  sync.Mutex
	attributionCacheGen int64
	attributionCache    = map[attributionCacheKey]attributionCacheEntry{}
)

// flushGeneration reads the rollup generation marker; 0 means "unknown" and
// disables caching rather than risking a stale cache that never invalidates.
func (s *webServer) flushGeneration() int64 {
	b, err := os.ReadFile(filepath.Join(s.logDir, "stats.json"))
	if err != nil {
		return 0
	}
	var st RuntimeStats
	if json.Unmarshal(b, &st) != nil || st.LastFlushAt.IsZero() {
		return 0
	}
	return st.LastFlushAt.UnixNano()
}

func (s *webServer) flowAttributions(from, to time.Time, clientFilter string) map[string]apiFlowAttribution {
	// Round the window outward to whole minutes so back-to-back requests ("now"
	// differs by milliseconds) share a cache key; widening by <1min is noise
	// against the 2h/6h evidence lookback.
	fromMin := from.Unix() / 60
	toMin := (to.Unix() + 59) / 60
	from = time.Unix(fromMin*60, 0)
	to = time.Unix(toMin*60, 0)
	gen := s.flushGeneration()
	if gen == 0 {
		return s.scanFlowAttributions(from, to, clientFilter)
	}
	key := attributionCacheKey{gen: gen, fromMin: fromMin, toMin: toMin, client: clientFilter}
	attributionCacheMu.Lock()
	if attributionCacheGen != gen {
		// New rollup generation: everything cached describes the previous flush.
		attributionCache = map[attributionCacheKey]attributionCacheEntry{}
		attributionCacheGen = gen
	}
	if e, ok := attributionCache[key]; ok {
		attributionCacheMu.Unlock()
		return e.val
	}
	attributionCacheMu.Unlock()

	val := s.scanFlowAttributions(from, to, clientFilter)

	attributionCacheMu.Lock()
	if attributionCacheGen == gen {
		if len(attributionCache) >= attributionCacheMax {
			// Evict the oldest entry; the cache only has to survive one generation.
			var oldestKey attributionCacheKey
			var oldest time.Time
			first := true
			for k, e := range attributionCache {
				if first || e.added.Before(oldest) {
					oldestKey, oldest, first = k, e.added, false
				}
			}
			delete(attributionCache, oldestKey)
		}
		attributionCache[key] = attributionCacheEntry{val: val, added: time.Now()}
	}
	attributionCacheMu.Unlock()
	return val
}

func (s *webServer) scanFlowAttributions(from, to time.Time, clientFilter string) map[string]apiFlowAttribution {
	// DNS/SNI often happen before the byte-heavy flow window. The first two hours
	// are strong evidence; older matches are a low-priority fallback for CDN IPs
	// whose connection outlives the visible handshakes.
	strongCutoff := from.Add(-attributionStrongLookback)
	cutoff := from.Add(-attributionMaxLookback)
	type candMap map[string]*attributionCandidate
	byFlow := map[string]candMap{}
	add := func(client, ip, domain, source string, priority int, ts time.Time) {
		domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
		if client == "" || net.ParseIP(ip) == nil || domain == "" || net.ParseIP(domain) != nil {
			return
		}
		k := flowAttributionKey(client, ip)
		m := byFlow[k]
		if m == nil {
			m = candMap{}
			byFlow[k] = m
		}
		c := m[domain]
		if c == nil {
			c = &attributionCandidate{Domain: domain, Source: source, Priority: priority, Last: ts}
			m[domain] = c
		}
		c.Hits++
		if priority > c.Priority {
			c.Priority = priority
			c.Source = source
		}
		if ts.After(c.Last) {
			c.Last = ts
		}
	}

	scanLogReverse(filepath.Join(s.logDir, "tls.jsonl"), func(line []byte) bool {
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
		if clientFilter != "" && rec.Client != clientFilter {
			return true
		}
		source := "TLS SNI"
		priority := 3
		if rec.Protocol == "quic" {
			source = "QUIC SNI"
		}
		if rec.TS.Before(strongCutoff) {
			source = "historical " + source
			priority = 1
		}
		add(rec.Client, rec.RemoteIP, rec.ServerName, source, priority, rec.TS)
		return true
	})

	scanLogReverse(filepath.Join(s.logDir, "dns.jsonl"), func(line []byte) bool {
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
		if clientFilter != "" && rec.Client != clientFilter {
			return true
		}
		for _, ans := range rec.Answers {
			if ans.Type == "A" || ans.Type == "AAAA" {
				source := "DNS answer"
				priority := 2
				if rec.TS.Before(strongCutoff) {
					source = "historical DNS answer"
					priority = 1
				}
				add(rec.Client, ans.Value, rec.Query, source, priority, rec.TS)
			}
		}
		return true
	})

	out := map[string]apiFlowAttribution{}
	for k, candidates := range byFlow {
		rows := make([]*attributionCandidate, 0, len(candidates))
		for _, c := range candidates {
			rows = append(rows, c)
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].Priority != rows[j].Priority {
				return rows[i].Priority > rows[j].Priority
			}
			if rows[i].Hits != rows[j].Hits {
				return rows[i].Hits > rows[j].Hits
			}
			if !rows[i].Last.Equal(rows[j].Last) {
				return rows[i].Last.After(rows[j].Last)
			}
			return rows[i].Domain < rows[j].Domain
		})
		if len(rows) == 0 {
			continue
		}
		names := make([]string, 0, min(len(rows), attributionMaxCandidates))
		for _, c := range rows {
			names = append(names, c.Domain)
			if len(names) >= attributionMaxCandidates {
				break
			}
		}
		out[k] = apiFlowAttribution{AppTarget: rows[0].Domain, Source: rows[0].Source, Candidates: names}
	}
	return out
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
	// EncryptedDNS: the window shows DoH/DoT evidence (known resolver SNI or
	// port 853), so dns.jsonl is incomplete for this client and domain
	// attribution may undercount.
	EncryptedDNS bool        `json:"encrypted_dns"`
	Verdict      *apiVerdict `json:"verdict,omitempty"`
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
	var minOver1MB, minOver100KB int
	var lastAnyMin, lastSigMin int64 = -1, -1
	for i, b := range series {
		if b == 0 {
			continue
		}
		lastAnyMin = startMinute + int64(i)
		if b > significantMinuteBytes {
			minOver100KB++
			lastSigMin = startMinute + int64(i)
		}
		if b > heavyMinuteBytes {
			minOver1MB++
		}
	}
	fresh := freshWithin(lastTLS, now, freshSignalWindow) || freshWithin(lastDNS, now, freshSignalWindow)
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
	case minOver1MB >= activeHeavyMinutes:
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
	case total >= activeTotalBytes:
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

// unknownVerdict is what the classifier degrades to when the rollup DB cannot
// be read: with no byte evidence at all we must not brand a device "silent,
// high confidence" — an outage must never read as quiet.
func unknownVerdict() apiVerdict {
	return apiVerdict{Status: "unknown", Confidence: "low", Reasons: []string{"rollup unavailable"}}
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
	series, dbErr := s.throughputWindow(now.Add(-d), now)
	if dbErr != nil {
		logRateLimited("rollup", "wgflow web: rollup read: %v", dbErr)
	}
	writeJSON(w, map[string]any{"since": d.String(), "db_ok": dbErr == nil, "points": series})
}

// throughputSeries keeps the historical error-swallowing signature for callers
// that only care about a best-effort series; handlers use throughputWindow so
// they can report db_ok honestly.
func (s *webServer) throughputSeries(cutoff, now time.Time) []tPoint {
	series, _ := s.throughputWindow(cutoff, now)
	return series
}

func (s *webServer) throughputWindow(cutoff, now time.Time) ([]tPoint, error) {
	per := map[int64]*tPoint{}
	db, err := openRollupReadOnly(s.rollupPath)
	if err != nil {
		return zeroThroughputSeries(cutoff, now, per), err
	}
	defer db.Close()
	err = db.View(func(tx *bolt.Tx) error {
		scanMinuteKeyRange(tx, rollupClientBucket, cutoff.Unix()/60, now.Unix()/60, func(m int64, _ string, v []byte) {
			tot := decodeRollupTotalValue(v)
			p := per[m]
			if p == nil {
				p = &tPoint{T: m * 60}
				per[m] = p
			}
			p.Down += tot.DownloadBytes
			p.Up += tot.UploadBytes
		})
		return nil
	})
	return zeroThroughputSeries(cutoff, now, per), err
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
	snaps, dbErr := s.snapshotWindow(cutoff, now)
	if dbErr != nil {
		logRateLimited("rollup", "wgflow web: rollup read: %v", dbErr)
	}
	dbOK := dbErr == nil
	// Surface configured-but-silent devices so the board shows who's offline, not
	// just who had traffic (the roster comes from clients.yaml).
	for _, dev := range s.aliases.Roster() {
		if snaps[dev] == nil {
			snaps[dev] = &snapClient{cats: map[string]uint64{}}
		}
	}
	sites, lastTLS, encDNS := s.lastSitesByClient(cutoff)
	lastDNS := s.lastDNSByClient(cutoff)
	clients := make([]*apiClient, 0, len(snaps))
	for name, sc := range snaps {
		cats := mapToShares(sc.cats)
		c := &apiClient{
			Name:         name,
			Down:         sc.down,
			Up:           sc.up,
			Total:        sc.down + sc.up,
			Cats:         cats,
			Series:       sc.series,
			CurrentSite:  sites[name],
			DeviceKind:   s.resolveDeviceKind(name),
			Person:       s.aliases.Person(name),
			EncryptedDNS: encDNS[name],
		}
		if len(cats) > 0 {
			c.TopCategory = cats[0].Category
		}
		v := unknownVerdict()
		if dbOK {
			v = classify(sc.series, startMinute, c.Total, cats, c.DeviceKind, lastTLS[name], lastDNS[name], now, loggerOK)
		}
		c.Verdict = &v
		clients = append(clients, c)
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].Total > clients[j].Total })
	writeJSON(w, map[string]any{"since": d.String(), "logger_ok": loggerOK, "db_ok": dbOK, "clients": clients})
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
	EncryptedDNS    bool          `json:"encrypted_dns"`
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

	snaps, dbErr := s.snapshotWindow(cutoff, now)
	if dbErr != nil {
		logRateLimited("rollup", "wgflow web: rollup read: %v", dbErr)
	}
	dbOK := dbErr == nil
	sites, lastTLS, encDNS := s.recentSitesByClient(cutoff, snapshotSitesPerClient)
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
		v := unknownVerdict()
		if dbOK {
			v = classify(sc.series, startMinute, total, cats, devKind, lastTLS[name], lastDNS[name], now, loggerOK)
		}
		entry := apiSnapshotClient{
			Name: name, Person: s.aliases.Person(name), DeviceKind: devKind,
			Down: sc.down, Up: sc.up, Total: total,
			MinutesOver100K: sc.minOver100k, MinutesOver1MB: sc.minOver1mb,
			Cats: cats, RecentSites: sites[name], EncryptedDNS: encDNS[name], Verdict: v,
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
		"db_ok":        dbOK,
		"clients":      out,
	})
}

type snapClient struct {
	series                  []uint64
	down, up                uint64
	minOver100k, minOver1mb int
	cats                    map[string]uint64
}

// snapshotFromRollup keeps the historical error-swallowing signature; handlers
// use snapshotWindow so an unreadable DB surfaces as db_ok=false, not zeros.
func (s *webServer) snapshotFromRollup(cutoff, now time.Time) map[string]*snapClient {
	res, _ := s.snapshotWindow(cutoff, now)
	return res
}

// snapshotWindow reads per-client minute totals (zero-filled series + down/up
// + >100KB/>1MB minute counts) and per-client category sums straight from the
// binary buckets — one bbolt open, no JSON-target scan.
func (s *webServer) snapshotWindow(cutoff, now time.Time) (map[string]*snapClient, error) {
	res := map[string]*snapClient{}
	startMin := cutoff.Unix() / 60
	endMin := now.Unix() / 60
	n := int(endMin - startMin + 1)
	if n <= 0 {
		return res, nil
	}
	db, err := openRollupReadOnly(s.rollupPath)
	if err != nil {
		return res, err
	}
	defer db.Close()
	err = db.View(func(tx *bolt.Tx) error {
		scanMinuteKeyRange(tx, rollupClientBucket, startMin, endMin, func(m int64, name string, v []byte) {
			idx := int(m - startMin)
			if idx < 0 || idx >= n {
				return
			}
			sc := res[name]
			if sc == nil {
				sc = &snapClient{series: make([]uint64, n), cats: map[string]uint64{}}
				res[name] = sc
			}
			tot := decodeRollupTotalValue(v)
			sc.series[idx] += tot.DownloadBytes + tot.UploadBytes
			sc.down += tot.DownloadBytes
			sc.up += tot.UploadBytes
		})
		// category sums, seeked per client by prefix so we only touch recent minutes
		for name, sc := range res {
			scanClientCategoryRange(tx, name, startMin, endMin, func(_ int64, cat string, tot RollupTotal) {
				sc.cats[cat] += tot.DownloadBytes + tot.UploadBytes
			})
		}
		return nil
	})
	for _, sc := range res {
		for _, b := range sc.series {
			if b > significantMinuteBytes {
				sc.minOver100k++
			}
			if b > heavyMinuteBytes {
				sc.minOver1mb++
			}
		}
	}
	return res, err
}

// encryptedDNSNames are SNIs that identify well-known DoH/DoT resolvers, plus
// the iCloud Private Relay hosts (which bundle ODoH). A handshake to one of
// these means the client's DNS is (partly) invisible to dns.jsonl — domain
// attribution may undercount, and the UI must say so instead of implying a
// complete log.
var encryptedDNSNames = map[string]bool{
	"one.one.one.one":     true,
	"dns.google":          true,
	"cloudflare-dns.com":  true,
	"dns.adguard-dns.com": true,
	"doh.opendns.com":     true,
	"mask.icloud.com":     true,
	"mask-h2.icloud.com":  true,
	"mask-api.icloud.com": true,
	"dns.quad9.net":       true,
}

// tlsRecordSuggestsEncryptedDNS reports whether one tls.jsonl record is
// evidence of encrypted DNS: a known resolver SNI, or any handshake on the
// dedicated DoT/DoQ port.
func tlsRecordSuggestsEncryptedDNS(rec TLSRecord) bool {
	return encryptedDNSNames[strings.ToLower(rec.ServerName)] || rec.RemotePort == 853
}

// recentSitesByClient collects up to limit distinct recent SNIs per client
// (newest first) plus the last TLS time, from one tls.jsonl tail scan. The
// same walk also flags clients with encrypted-DNS evidence in the window
// (known DoH/DoT SNI or port 853) — deliberately piggybacked here so the
// board/snapshot endpoints get the signal without a second file scan. Flows
// to port 853 without a captured handshake are covered on the client-detail
// endpoint, which already loads per-target flows.
func (s *webServer) recentSitesByClient(cutoff time.Time, limit int) (map[string][]string, map[string]time.Time, map[string]bool) {
	sites := map[string][]string{}
	seen := map[string]map[string]bool{}
	last := map[string]time.Time{}
	encDNS := map[string]bool{}
	scanLogReverse(filepath.Join(s.logDir, "tls.jsonl"), func(line []byte) bool {
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
		if tlsRecordSuggestsEncryptedDNS(rec) {
			encDNS[rec.Client] = true
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
	return sites, last, encDNS
}

// lastSitesByClient returns, per client, the most recent SNI plus its timestamp
// (the timestamp feeds the classifier's "fresh TLS" signal — nearly free since
// the file is walked anyway) and the encrypted-DNS flag from the same walk. It
// is the limit=1 case of recentSitesByClient.
func (s *webServer) lastSitesByClient(cutoff time.Time) (map[string]string, map[string]time.Time, map[string]bool) {
	sites, last, encDNS := s.recentSitesByClient(cutoff, 1)
	res := make(map[string]string, len(sites))
	for name, list := range sites {
		if len(list) > 0 {
			res[name] = list[0]
		}
	}
	return res, last, encDNS
}

// lastDNSByClient reverse-scans dns.jsonl within the window for each client's
// most recent query time — the second half of the classifier's freshness signal.
func (s *webServer) lastDNSByClient(cutoff time.Time) map[string]time.Time {
	last := map[string]time.Time{}
	scanLogReverse(filepath.Join(s.logDir, "dns.jsonl"), func(line []byte) bool {
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
	return time.Since(st.UpdatedAt) < loggerHeartbeatMax
}

// seriesByClient returns a zero-filled per-minute byte total (download+upload)
// for every client over [cutoff, now], for rendering per-client sparklines.
// A nil db (open already failed upstream) yields an empty result.
func (s *webServer) seriesByClient(db *bolt.DB, cutoff, now time.Time) (map[string][]uint64, error) {
	res := map[string][]uint64{}
	startMin := cutoff.Unix() / 60
	endMin := now.Unix() / 60
	n := int(endMin - startMin + 1)
	if n <= 0 || db == nil {
		return res, nil
	}
	err := db.View(func(tx *bolt.Tx) error {
		scanMinuteKeyRange(tx, rollupClientBucket, startMin, endMin, func(m int64, name string, v []byte) {
			idx := int(m - startMin)
			if idx < 0 || idx >= n {
				return
			}
			arr := res[name]
			if arr == nil {
				arr = make([]uint64, n)
				res[name] = arr
			}
			tot := decodeRollupTotalValue(v)
			arr[idx] += tot.DownloadBytes + tot.UploadBytes
		})
		return nil
	})
	return res, err
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
	// One bbolt open serves the whole request: flows, series, ribbon, and day
	// timeline used to each open (and flock) the DB separately.
	db, dbErr := openRollupReadOnly(s.rollupPath)
	if dbErr == nil {
		defer db.Close()
	} else {
		db = nil
	}
	aggList, flowsErr := s.clientFlowsWindow(db, name, from, to)
	seriesMap, seriesErr := s.seriesByClient(db, from, to)
	for _, e := range []error{flowsErr, seriesErr} {
		if dbErr == nil {
			dbErr = e
		}
	}
	if dbErr != nil {
		logRateLimited("rollup", "wgflow web: rollup read: %v", dbErr)
	}
	dbOK := dbErr == nil
	series, hasRollupRows := seriesMap[name]
	// A name with no rollup rows in the window and no mention in the configs is
	// a typo or a removed peer: 404 beats a fabricated all-zero client. When the
	// rollup DB itself is unreadable we cannot prove absence, so we don't 404.
	if dbOK && !hasRollupRows && len(aggList) == 0 && !s.clientConfigured(name) {
		writeJSONError(w, http.StatusNotFound, "unknown client")
		return
	}
	attrs := s.flowAttributions(from, to, name)
	var down, up uint64
	cat := map[string]uint64{}
	targets := make([]apiFlow, 0, len(aggList))
	for _, a := range aggList {
		f := newAPIFlowWithAttribution(a, attrs)
		down += a.Down
		up += a.Up
		cat[f.Category] += f.Total
		targets = append(targets, f)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Total > targets[j].Total })
	if len(targets) > detailTopTargets {
		targets = targets[:detailTopTargets]
	}
	recentDNS := s.recentDNSForClient(name, recentCutoff, to, detailRecentEvents)
	recentTLS := s.recentTLSForClient(name, recentCutoff, to, detailRecentEvents)
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
	verdict := unknownVerdict()
	if dbOK {
		verdict = classify(series, from.Unix()/60, down+up, cats, devKind, lastTLS, lastDNS, to, loggerOK)
	}
	// Encrypted-DNS evidence: flows to the DoT/DoQ port in the window (the
	// per-target aggregates are already loaded here — the board endpoints only
	// have the cheaper SNI-based signal), or a known resolver SNI / port-853
	// handshake within the window slice of the recent-TLS list.
	encryptedDNS := false
	for _, a := range aggList {
		if a.Port == 853 {
			encryptedDNS = true
			break
		}
	}
	for _, rec := range recentTLS {
		if encryptedDNS {
			break
		}
		if !rec.TS.Before(from) && tlsRecordSuggestsEncryptedDNS(rec) {
			encryptedDNS = true
		}
	}
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
		"minutes":     s.minuteRibbon(db, name, from, to),
		"recent_dns":  recentDNS,
		"recent_tls":  recentTLS,
		"day":           s.dayTimeline(db, name),
		"device_kind":   devKind,
		"person":        s.aliases.Person(name),
		"encrypted_dns": encryptedDNS,
		"logger_ok":     loggerOK,
		"db_ok":         dbOK,
		"verdict":       verdict,
	})
}

// clientConfigured reports whether a client name is declared anywhere: in
// clients.yaml or as a "### Client <name>" comment in the WireGuard config
// (the same convention ClientMap.Load keys on). Configured-but-silent devices
// must keep answering with zeros, not 404.
func (s *webServer) clientConfigured(name string) bool {
	for _, dev := range s.aliases.Roster() {
		if dev == name {
			return true
		}
	}
	lines, err := readLines(s.wgConfig)
	if err != nil {
		return false
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "### Client ") && strings.TrimSpace(strings.TrimPrefix(line, "### Client ")) == name {
			return true
		}
	}
	return false
}

// clientFlowsWindow aggregates one client's per-target flows over [from, to] from
// flow_minute_v1, bounded on both ends (so an explicit ?to= is honored).
// A nil db (open already failed upstream) yields an empty result.
func (s *webServer) clientFlowsWindow(db *bolt.DB, name string, from, to time.Time) ([]*TopAgg, error) {
	if db == nil {
		return nil, nil
	}
	fromMin := from.Unix() / 60
	toMin := to.Unix() / 60
	aggs := map[string]*TopAgg{}
	err := db.View(func(tx *bolt.Tx) error {
		scanMinuteKeyRange(tx, rollupBucket, fromMin, toMin, func(_ int64, _ string, v []byte) {
			var row RollupRow
			if json.Unmarshal(v, &row) != nil || row.Client != name {
				return
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
		})
		return nil
	})
	out := make([]*TopAgg, 0, len(aggs))
	for _, a := range aggs {
		out = append(out, a)
	}
	return out, err
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

// clientMinuteRibbon keeps the historical open-per-call signature; the detail
// handler uses minuteRibbon with its already-open handle.
func (s *webServer) clientMinuteRibbon(name string, from, to time.Time) []apiMinute {
	db, err := openRollupReadOnly(s.rollupPath)
	if err != nil {
		logRateLimited("rollup", "wgflow web: rollup read: %v", err)
		db = nil
	} else {
		defer db.Close()
	}
	return s.minuteRibbon(db, name, from, to)
}

// minuteRibbon returns one zero-filled row per MSK minute over [from, to]
// (silent minutes included) with the dominant category — bytes/flags from the
// binary buckets only, no domain join. Capped so it can't be asked to render an
// unbounded ribbon; nil means "window too wide, don't show the ribbon".
func (s *webServer) minuteRibbon(db *bolt.DB, name string, from, to time.Time) []apiMinute {
	fromMin := from.Unix() / 60
	toMin := to.Unix() / 60
	n := int(toMin - fromMin + 1)
	if n <= 0 || n > ribbonMaxMinutes {
		return nil
	}
	out := make([]apiMinute, n)
	cats := make([]map[string]uint64, n)
	for i := range out {
		out[i].T = (fromMin + int64(i)) * 60
	}
	if db == nil {
		return out
	}
	viewErr := db.View(func(tx *bolt.Tx) error {
		scanMinuteKeyRange(tx, rollupClientBucket, fromMin, toMin, func(m int64, client string, v []byte) {
			if client != name {
				return
			}
			tot := decodeRollupTotalValue(v)
			idx := int(m - fromMin)
			out[idx].Down += tot.DownloadBytes
			out[idx].Up += tot.UploadBytes
			out[idx].Bytes += tot.DownloadBytes + tot.UploadBytes
		})
		scanClientCategoryRange(tx, name, fromMin, toMin, func(m int64, cat string, tot RollupTotal) {
			idx := int(m - fromMin)
			if cats[idx] == nil {
				cats[idx] = map[string]uint64{}
			}
			cats[idx][cat] += tot.DownloadBytes + tot.UploadBytes
		})
		return nil
	})
	if viewErr != nil {
		logRateLimited("rollup", "wgflow web: rollup read: %v", viewErr)
	}
	for i := range out {
		if cats[i] != nil {
			out[i].TopCategory = topKey(cats[i])
		}
		out[i].Over100K = out[i].Bytes > significantMinuteBytes
		out[i].Over1M = out[i].Bytes > heavyMinuteBytes
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
	scanLogReverse(filepath.Join(s.logDir, "tls.jsonl"), func(line []byte) bool {
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
	scanLogReverse(filepath.Join(s.logDir, "dns.jsonl"), func(line []byte) bool {
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
	scanLogReverse(filepath.Join(s.logDir, "dns.jsonl"), func(line []byte) bool {
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
	scanLogReverse(filepath.Join(s.logDir, "tls.jsonl"), func(line []byte) bool {
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

// clientDayTimeline keeps the historical open-per-call signature; the detail
// handler uses dayTimeline with its already-open handle.
func (s *webServer) clientDayTimeline(name string) []apiHour {
	db, err := openRollupReadOnly(s.rollupPath)
	if err != nil {
		logRateLimited("rollup", "wgflow web: rollup read: %v", err)
		db = nil
	} else {
		defer db.Close()
	}
	return s.dayTimeline(db, name)
}

// dayTimeline buckets today's traffic by hour of day, starting at local
// midnight — NOT a sliding 24h window: folding yesterday evening into the same
// hour-of-day buckets made 16:00 yesterday indistinguishable from 16:00 today.
// Hours after the current one stay zero (the frontend dims them; contract
// agreed with the UI side). Prefers the compact client-category index; a DB
// from before that bucket existed falls back to the heavy flow_minute_v1 scan.
func (s *webServer) dayTimeline(db *bolt.DB, name string) []apiHour {
	buckets := make([]apiHour, 24)
	for i := range buckets {
		buckets[i] = apiHour{Hour: i, Cats: map[string]uint64{}}
	}
	if db == nil {
		return buckets
	}
	loc := s.location()
	now := time.Now().In(loc)
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	fromMinute := midnight.Unix() / 60
	// Ignore rows past the current minute (clock skew) so future hours stay zero.
	nowMinute := now.Unix() / 60
	if err := db.View(func(tx *bolt.Tx) error {
		if scanClientCategoryRange(tx, name, fromMinute, nowMinute, func(minute int64, cat string, tot RollupTotal) {
			h := hourInLocation(minute, loc)
			bt := tot.DownloadBytes + tot.UploadBytes
			buckets[h].Cats[cat] += bt
			buckets[h].Total += bt
		}) {
			return nil
		}
		scanMinuteKeyRange(tx, rollupBucket, fromMinute, nowMinute, func(minute int64, _ string, v []byte) {
			var row RollupRow
			if json.Unmarshal(v, &row) != nil || row.Client != name {
				return
			}
			h := hourInLocation(minute, loc)
			bt := row.DownloadBytes + row.UploadBytes
			buckets[h].Cats[row.Category] += bt
			buckets[h].Total += bt
		})
		return nil
	}); err != nil {
		logRateLimited("rollup", "wgflow web: rollup read: %v", err)
	}
	return buckets
}

func (s *webServer) handleTraffic(w http.ResponseWriter, r *http.Request) {
	d := parseSince(r, 15*time.Minute)
	now := time.Now()
	cutoff := now.Add(-d)
	q := r.URL.Query()
	clientFilter := q.Get("client")
	catFilter := q.Get("category")
	protoFilter := q.Get("proto")
	search := strings.ToLower(q.Get("q"))
	limit := atoiDefault(q.Get("limit"), trafficDefaultLimit)
	aggs := map[string]*TopAgg{}
	_, dbErr := aggregateFromRollup(s.rollupPath, cutoff, clientFilter, aggs)
	if dbErr != nil {
		logRateLimited("rollup", "wgflow web: rollup read: %v", dbErr)
	}
	attrs := s.flowAttributions(cutoff, now, clientFilter)
	rows := make([]apiFlow, 0, len(aggs))
	for _, a := range aggs {
		f := newAPIFlowWithAttribution(a, attrs)
		if catFilter != "" && catFilter != "all" && f.Category != catFilter {
			continue
		}
		if protoFilter != "" && protoFilter != "all" && f.Proto != protoFilter {
			continue
		}
		searchText := strings.ToLower(f.Target + " " + f.AppTarget + " " + f.ResolvedTarget + " " + f.TargetOrg)
		if search != "" && !strings.Contains(searchText, search) {
			continue
		}
		rows = append(rows, f)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Total > rows[j].Total })
	total := len(rows)
	if limit > 0 && limit < len(rows) {
		rows = rows[:limit]
	}
	writeJSON(w, map[string]any{"since": d.String(), "db_ok": dbErr == nil, "total": total, "rows": rows})
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
	now := time.Now()
	cutoff := now.Add(-d)
	aggs := map[string]*TopAgg{}
	_, dbErr := aggregateFromRollup(s.rollupPath, cutoff, "", aggs)
	if dbErr != nil {
		logRateLimited("rollup", "wgflow web: rollup read: %v", dbErr)
	}
	attrs := s.flowAttributions(cutoff, now, "")
	type acc struct {
		down, up uint64
		clients  map[string]uint64
		targets  map[string]uint64
	}
	m := map[string]*acc{}
	for _, a := range aggs {
		f := newAPIFlowWithAttribution(a, attrs)
		x := m[f.Category]
		if x == nil {
			x = &acc{clients: map[string]uint64{}, targets: map[string]uint64{}}
			m[f.Category] = x
		}
		x.down += f.Down
		x.up += f.Up
		x.clients[f.Client] += f.Total
		x.targets[apiFlowDisplayTarget(f)] += f.Total
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
	writeJSON(w, map[string]any{"since": d.String(), "db_ok": dbErr == nil, "categories": out})
}

func (s *webServer) handleDNS(w http.ResponseWriter, r *http.Request) {
	d := parseSince(r, 15*time.Minute)
	cutoff := time.Now().Add(-d)
	q := r.URL.Query()
	clientFilter := q.Get("client")
	qtype := q.Get("qtype")
	errorsOnly := q.Get("errors") == "1" || q.Get("errors") == "true"
	search := strings.ToLower(q.Get("q"))
	limit := atoiDefault(q.Get("limit"), dnsDefaultLimit)
	out := []DNSRecord{}
	errCount := 0
	scanLogReverse(filepath.Join(s.logDir, "dns.jsonl"), func(line []byte) bool {
		var rec DNSRecord
		if json.Unmarshal(line, &rec) != nil {
			return true
		}
		if rec.TS.Before(cutoff) {
			return false
		}
		if clientFilter != "" && rec.Client != clientFilter {
			return true
		}
		if qtype != "" && qtype != "all" && rec.QType != qtype {
			return true
		}
		if search != "" && !strings.Contains(strings.ToLower(rec.Query), search) {
			return true
		}
		// Counted after the client/qtype/search filters so the badge matches the
		// list the user is looking at ("12 errors" over 2 visible rows was a lie).
		if rec.RCode != 0 {
			errCount++
		}
		if errorsOnly && rec.RCode == 0 {
			return true
		}
		// Stop collecting once the page is full (we used to buffer the whole
		// window and truncate afterwards); the scan itself continues so the
		// error badge still covers the entire clamped window.
		if len(out) < limit {
			out = append(out, rec)
		}
		return true
	})
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
	scanLogReverse(filepath.Join(s.logDir, "tls.jsonl"), func(line []byte) bool {
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
		if len(recent) < tlsRecentSample {
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
	byClient, byCategory, rows, dbErr := aggregateReportTotalsFromRollup(s.rollupPath, cutoff)
	if dbErr != nil {
		logRateLimited("rollup", "wgflow web: rollup read: %v", dbErr)
	}
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
		"db_ok":       dbErr == nil,
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
	// A JSONL line is at most a few KB; anything beyond this is binary junk or
	// corruption in place of the log. Without a cap, a newline-free file would
	// accumulate into one carry the size of the whole file.
	const maxCarry = 1 << 20
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
			if len(carry) > maxCarry {
				// Drop the oversized "line"; its fragments fail JSON parsing in
				// callers and get skipped, which beats buffering the file in RAM.
				carry = nil
			}
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
