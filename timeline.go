package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Activity timeline: per-minute service aggregation for one client, clustered
// into sessions ("this window of minutes was one stretch of use, headlined by
// picsart.com, with ad SDKs alongside").
//
// Everything here is READ-TIME: the rollup schema is untouched, the minute rows
// are the same flow_minute_v1 rows the detail endpoint reads, and the "new
// service" evidence comes from the tls.jsonl/dns.jsonl handshake logs. Nothing
// in the payload phrases a conclusion — the server emits structured facts
// (bytes, roles, first-seen flags, a leader candidate) and the UI does the
// wording. A leader is an inference and is labeled as such by the client.
const (
	// timelineDefaultWindow is the window ?since= defaults to.
	timelineDefaultWindow = 30 * time.Minute
	// timelineMaxMinutes bounds how wide a timeline may be rendered. A wider
	// window is not an error: the endpoint answers 200 with null minutes and a
	// note, the same "nil, not error" contract the ribbon uses.
	timelineMaxMinutes = 360
	// timelineSessionGap is how long a silence has to last before one stretch of
	// activity is considered finished. 5 minutes is the valley of the measured
	// distribution of pauses between "new domain first seen" events on the
	// production VPN (15 days, 12 clients: p50 = 2 s, 57 % ≤ 5 s, then a second
	// mode starting around 5 min — app launches vs. quiet), so it separates
	// launches without splitting one app's own bursts. The gap is measured
	// between minute STARTS, so ?gap=60 (the floor) makes every active minute
	// its own session and ?gap=120 still bridges a single silent minute.
	timelineSessionGap    = 5 * time.Minute
	timelineMinSessionGap = time.Minute
	timelineMaxSessionGap = 15 * time.Minute
	// timelineSessionServices caps the per-session service list; the leader and
	// the SDK list are computed from the full list before this truncation.
	timelineSessionServices = 12
	// timelineBaselineCacheMax bounds the first-seen cache, mirroring
	// attributionCacheMax: it only has to survive one flush generation.
	timelineBaselineCacheMax = 32
)

// timelineInfraCategories are the "whose backbone" labels that must never
// headline a session: "the person used Cloudflare" is not an answer to "what
// were they doing".
var timelineInfraCategories = map[string]bool{
	"cloudflare": true,
	"aws":        true,
	"cdn":        true,
}

type apiTimelineService struct {
	Service  string `json:"service"`
	Role     string `json:"role"`
	Category string `json:"category"`
	Bytes    uint64 `json:"bytes"`
	Down     uint64 `json:"down"`
	Up       uint64 `json:"up"`
	// New marks the minute in which this service's first handshake/query of the
	// window happened, with no trace of it in the preceding two hours.
	New bool `json:"new"`
	// Unnamed marks a bare-IP aggregate: Service is then a network owner
	// ("Google", "Cloudflare") or empty, never a hostname.
	Unnamed bool `json:"unnamed"`
}

type apiTimelineMinute struct {
	T        int64                `json:"t"` // unix seconds at the minute start
	Bytes    uint64               `json:"bytes"`
	Down     uint64               `json:"down"`
	Up       uint64               `json:"up"`
	Services []apiTimelineService `json:"services"`
}

type apiTimelineSessionService struct {
	Service   string `json:"service"`
	Role      string `json:"role"`
	Category  string `json:"category"`
	Bytes     uint64 `json:"bytes"`
	Down      uint64 `json:"down"`
	Up        uint64 `json:"up"`
	Direction string `json:"direction"`
}

type apiTimelineSession struct {
	From      int64  `json:"from"` // first active minute, unix seconds
	To        int64  `json:"to"`   // end of the last active minute (exclusive)
	Minutes   int    `json:"minutes"`
	Bytes     uint64 `json:"bytes"`
	Down      uint64 `json:"down"`
	Up        uint64 `json:"up"`
	Direction string `json:"direction"`
	// Leader is the service that most plausibly headlines the session, or null
	// when nothing qualifies (an ad-SDK-only stretch has no headline).
	Leader      *apiTimelineSessionService  `json:"leader"`
	Services    []apiTimelineSessionService `json:"services"`
	SDK         []string                    `json:"sdk"`
	NewServices []string                    `json:"new_services"`
}

type apiTimeline struct {
	Name       string               `json:"name"`
	From       int64                `json:"from"`
	To         int64                `json:"to"`
	GapSeconds int                  `json:"gap_seconds"`
	LoggerOK   bool                 `json:"logger_ok"`
	DBOK       bool                 `json:"db_ok"`
	Note       string               `json:"note,omitempty"`
	Minutes    []apiTimelineMinute  `json:"minutes"`
	Sessions   []apiTimelineSession `json:"sessions"`
}

// parseTimelineGap reads ?gap= (seconds) and clamps it into a range where the
// notion of "one session" still means something: under a minute every silent
// minute would split a session, over fifteen a whole evening folds into one.
func parseTimelineGap(r *http.Request) time.Duration {
	v := r.URL.Query().Get("gap")
	if v == "" {
		return timelineSessionGap
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return timelineSessionGap
	}
	d := time.Duration(n) * time.Second
	if d < timelineMinSessionGap {
		return timelineMinSessionGap
	}
	if d > timelineMaxSessionGap {
		return timelineMaxSessionGap
	}
	return d
}

// timelineKey identifies one aggregated service inside a minute or a session.
// Unnamed is part of the key: an org-labeled bare-IP aggregate and a named
// service that happens to share the label are different evidence.
type timelineKey struct {
	Service string
	Role    string
	Unnamed bool
}

// timelineServiceAgg accumulates one timelineKey. Category is the STORED rollup
// category (never recomputed here — capture time owns that label); when rows
// with different stored categories fold together, the one carrying the most
// bytes wins, ties broken lexicographically so the output is deterministic.
type timelineServiceAgg struct {
	key      timelineKey
	category string
	catBytes uint64
	down, up uint64
	isNew    bool
}

func (a *timelineServiceAgg) bytes() uint64 { return a.down + a.up }

func (a *timelineServiceAgg) observeCategory(cat string, bytes uint64) {
	if a.category == "" || bytes > a.catBytes || (bytes == a.catBytes && cat < a.category) {
		a.category = cat
		a.catBytes = bytes
	}
}

// sortTimelineAggs orders by bytes desc, then service and role ascending so a
// polled timeline does not reshuffle rows that carry equal bytes.
func sortTimelineAggs(aggs []*timelineServiceAgg) {
	sort.Slice(aggs, func(i, j int) bool {
		bi, bj := aggs[i].bytes(), aggs[j].bytes()
		if bi != bj {
			return bi > bj
		}
		if aggs[i].key.Service != aggs[j].key.Service {
			return aggs[i].key.Service < aggs[j].key.Service
		}
		return aggs[i].key.Role < aggs[j].key.Role
	})
}

type timelineMinuteData struct {
	t        int64
	down, up uint64
	services []*timelineServiceAgg
	active   bool
}

// clientFlowsByMinute is clientFlowsWindow's sibling that keeps the minute: the
// same exact-prefix seek per minute (cost independent of household size), but
// folding per-target rows within each minute instead of across the window.
// A nil db (open already failed upstream) yields an empty result.
func (s *webServer) clientFlowsByMinute(ctx context.Context, db *bolt.DB, name string, from, to time.Time) (map[int64][]*TopAgg, error) {
	if db == nil {
		return nil, nil
	}
	fromMin := from.Unix() / 60
	toMin := to.Unix() / 60
	out := map[int64][]*TopAgg{}
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(rollupBucket)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for minute := fromMin; minute <= toMin; minute++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			prefix := []byte(fmt.Sprintf("%012d\t%s\t", minute, name))
			aggs := map[string]*TopAgg{}
			for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
				if err := ctx.Err(); err != nil {
					return err
				}
				var row RollupRow
				if json.Unmarshal(v, &row) != nil {
					continue
				}
				key := row.Category + "\t" + row.Target + "\t" + row.Proto + "\t" + strconv.Itoa(int(row.Port))
				a := aggs[key]
				if a == nil {
					a = &TopAgg{Client: row.Client, Category: row.Category, Target: row.Target, Proto: row.Proto, Port: row.Port}
					aggs[key] = a
					out[minute] = append(out[minute], a)
				}
				a.Down += row.DownloadBytes
				a.Up += row.UploadBytes
				a.DownP += row.DownloadPackets
				a.UpP += row.UploadPackets
			}
		}
		return nil
	})
	return out, err
}

// timelineResolve turns one rollup row into a (service, role, unnamed) identity.
// A named target is named by the service table; a bare IP first tries the
// attribution scan's app_target (the domain whose handshake claimed that IP for
// this client) and only then falls back to the network owner, which is labeled
// unnamed so the UI can say "без имени" instead of inventing a site.
func timelineResolve(a *TopAgg, attrs map[string]apiFlowAttribution) timelineKey {
	host := a.Target
	if net.ParseIP(a.Target) != nil {
		host = ""
		if attrs != nil {
			if attr := attrs[flowAttributionKey(a.Client, a.Target)]; attr.AppTarget != "" {
				host = attr.AppTarget
			}
		}
		if host == "" {
			_, org := enrichTargetNonBlocking(a.Target, "", a.Proto, a.Port)
			return timelineKey{Service: org, Unnamed: true}
		}
	}
	svc := targetService(host)
	if svc == "" {
		return timelineKey{Unnamed: true}
	}
	return timelineKey{Service: svc, Role: targetRole(host)}
}

// timelineBaseline is the "is this service new" evidence for one window: the
// earliest trace of each service inside [from, to], plus the set of services
// already seen in the two hours before it.
type timelineBaseline struct {
	first map[string]time.Time
	known map[string]bool
}

func (b timelineBaseline) isNewIn(service string, minuteStart int64) bool {
	if service == "" || b.known[service] {
		return false
	}
	ts, ok := b.first[service]
	if !ok {
		return false
	}
	sec := ts.Unix()
	return sec >= minuteStart && sec < minuteStart+60
}

// The baseline walk reads two hours of both JSONL logs. A polled timeline would
// redo that every 30s, so it is cached exactly like the attribution scan: keyed
// on the rollup flush generation (stats.json last_flush_at), whole map dropped
// when the generation moves, bounded size. gen == 0 means "unknown" and
// disables caching rather than risking an entry that never invalidates.
type timelineBaselineKey struct {
	gen     int64
	fromMin int64
	toMin   int64
	client  string
}

type timelineBaselineEntry struct {
	val   timelineBaseline
	added time.Time
}

var (
	timelineBaselineMu    sync.Mutex
	timelineBaselineGen   int64
	timelineBaselineCache = map[timelineBaselineKey]timelineBaselineEntry{}
)

func (s *webServer) timelineBaselineContext(ctx context.Context, from, to time.Time, client string) (timelineBaseline, error) {
	if err := ctx.Err(); err != nil {
		return timelineBaseline{}, err
	}
	// Round outward to whole minutes so back-to-back polls ("now" differs by
	// milliseconds) share a cache key.
	fromMin := from.Unix() / 60
	toMin := (to.Unix() + 59) / 60
	from = time.Unix(fromMin*60, 0)
	to = time.Unix(toMin*60, 0)
	gen := s.flushGeneration()
	if gen == 0 {
		return s.scanTimelineBaselineContext(ctx, from, to, client)
	}
	key := timelineBaselineKey{gen: gen, fromMin: fromMin, toMin: toMin, client: client}
	timelineBaselineMu.Lock()
	if timelineBaselineGen != gen {
		timelineBaselineCache = map[timelineBaselineKey]timelineBaselineEntry{}
		timelineBaselineGen = gen
	}
	if e, ok := timelineBaselineCache[key]; ok {
		timelineBaselineMu.Unlock()
		return e.val, nil
	}
	timelineBaselineMu.Unlock()

	val, err := s.scanTimelineBaselineContext(ctx, from, to, client)
	if err != nil {
		return timelineBaseline{}, err
	}

	timelineBaselineMu.Lock()
	if timelineBaselineGen == gen {
		if len(timelineBaselineCache) >= timelineBaselineCacheMax {
			var oldestKey timelineBaselineKey
			var oldest time.Time
			first := true
			for k, e := range timelineBaselineCache {
				if first || e.added.Before(oldest) {
					oldestKey, oldest, first = k, e.added, false
				}
			}
			delete(timelineBaselineCache, oldestKey)
		}
		timelineBaselineCache[key] = timelineBaselineEntry{val: val, added: time.Now()}
	}
	timelineBaselineMu.Unlock()
	return val, nil
}

// scanTimelineBaselineContext walks tls.jsonl and dns.jsonl backwards once each,
// from `to` down to from-attributionStrongLookback, bucketing every hostname it
// sees into "first seen inside the window" or "already known before it". The
// cached value is shared between requests and must never be mutated afterwards.
func (s *webServer) scanTimelineBaselineContext(ctx context.Context, from, to time.Time, client string) (timelineBaseline, error) {
	cutoff := from.Add(-attributionStrongLookback)
	base := timelineBaseline{first: map[string]time.Time{}, known: map[string]bool{}}
	note := func(host string, ts time.Time) {
		svc := targetService(host)
		if svc == "" {
			return
		}
		if ts.Before(from) {
			base.known[svc] = true
			return
		}
		if cur, ok := base.first[svc]; !ok || ts.Before(cur) {
			base.first[svc] = ts
		}
	}

	if err := scanLogReverseContext(ctx, filepath.Join(s.logDir, "tls.jsonl"), func(line []byte) bool {
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
		if (client != "" && rec.Client != client) || rec.ServerName == "" {
			return true
		}
		note(rec.ServerName, rec.TS)
		return true
	}); err != nil {
		return timelineBaseline{}, err
	}

	if err := scanLogReverseContext(ctx, filepath.Join(s.logDir, "dns.jsonl"), func(line []byte) bool {
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
		if (client != "" && rec.Client != client) || rec.Query == "" {
			return true
		}
		if !dnsRecordResolvesAddresses(rec) {
			return true
		}
		note(rec.Query, rec.TS)
		return true
	}); err != nil {
		return timelineBaseline{}, err
	}
	return base, nil
}

// dnsRecordResolvesAddresses keeps the baseline to lookups a client makes when
// it is about to connect somewhere (A/AAAA/HTTPS), so PTR and SRV noise cannot
// invent a "new service".
func dnsRecordResolvesAddresses(rec DNSRecord) bool {
	if timelineAddressQType(rec.QType) {
		return true
	}
	for _, ans := range rec.Answers {
		if timelineAddressQType(ans.Type) {
			return true
		}
	}
	return false
}

func timelineAddressQType(t string) bool {
	switch strings.ToUpper(strings.TrimSpace(t)) {
	case "A", "AAAA", "HTTPS":
		return true
	}
	return false
}

// timelineMinutes folds the per-minute rollup rows into per-minute service
// aggregates, marks first-seen services, and flags the minutes that count as
// activity. Only minutes that moved bytes are returned, ascending.
func timelineMinutes(byMinute map[int64][]*TopAgg, attrs map[string]apiFlowAttribution, base timelineBaseline, fromMin, toMin int64) []timelineMinuteData {
	out := make([]timelineMinuteData, 0, len(byMinute))
	for minute := fromMin; minute <= toMin; minute++ {
		rows := byMinute[minute]
		if len(rows) == 0 {
			continue
		}
		t := minute * 60
		md := timelineMinuteData{t: t}
		index := map[timelineKey]*timelineServiceAgg{}
		for _, a := range rows {
			key := timelineResolve(a, attrs)
			agg := index[key]
			if agg == nil {
				agg = &timelineServiceAgg{key: key, isNew: base.isNewIn(key.Service, t)}
				index[key] = agg
				md.services = append(md.services, agg)
			}
			agg.down += a.Down
			agg.up += a.Up
			agg.observeCategory(a.Category, a.Down+a.Up)
			md.down += a.Down
			md.up += a.Up
		}
		if md.down+md.up == 0 {
			continue
		}
		// "Real use" is measured on leader-capable services only: a minute of
		// pure CDN/push/DNS chatter is not somebody doing something.
		var activeBytes uint64
		hasNew := false
		for _, agg := range md.services {
			if isLeaderRole(agg.key.Role) {
				activeBytes += agg.bytes()
			}
			if agg.isNew {
				hasNew = true
			}
		}
		md.active = activeBytes > significantMinuteBytes || hasNew
		sortTimelineAggs(md.services)
		out = append(out, md)
	}
	return out
}

func timelineAPIMinutes(mins []timelineMinuteData) []apiTimelineMinute {
	out := make([]apiTimelineMinute, 0, len(mins))
	for _, md := range mins {
		row := apiTimelineMinute{T: md.t, Bytes: md.down + md.up, Down: md.down, Up: md.up,
			Services: make([]apiTimelineService, 0, len(md.services))}
		for _, agg := range md.services {
			row.Services = append(row.Services, apiTimelineService{
				Service: agg.key.Service, Role: agg.key.Role, Category: agg.category,
				Bytes: agg.bytes(), Down: agg.down, Up: agg.up,
				New: agg.isNew, Unnamed: agg.key.Unnamed,
			})
		}
		out = append(out, row)
	}
	return out
}

// timelineSessions clusters active minutes: consecutive active minutes closer
// together than gap belong to one session, a silence of gap or more closes it.
// Minutes inside a session's span contribute their bytes whether or not they
// were active themselves — the quiet minute in the middle of a download is part
// of the download.
func timelineSessions(mins []timelineMinuteData, gap time.Duration) []apiTimelineSession {
	gapSec := int64(gap / time.Second)
	out := []apiTimelineSession{}
	for i := 0; i < len(mins); {
		if !mins[i].active {
			i++
			continue
		}
		start, end := i, i
		for j := i + 1; j < len(mins); j++ {
			if !mins[j].active {
				continue
			}
			if mins[j].t-mins[end].t >= gapSec {
				break
			}
			end = j
		}
		out = append(out, buildTimelineSession(mins[start:end+1]))
		i = end + 1
	}
	return out
}

func buildTimelineSession(span []timelineMinuteData) apiTimelineSession {
	sess := apiTimelineSession{
		From:        span[0].t,
		To:          span[len(span)-1].t + 60,
		Minutes:     len(span),
		SDK:         []string{},
		NewServices: []string{},
	}
	index := map[timelineKey]*timelineServiceAgg{}
	order := []*timelineServiceAgg{}
	newSeen := map[string]bool{}
	for _, md := range span {
		sess.Down += md.down
		sess.Up += md.up
		for _, agg := range md.services {
			acc := index[agg.key]
			if acc == nil {
				acc = &timelineServiceAgg{key: agg.key}
				index[agg.key] = acc
				order = append(order, acc)
			}
			acc.down += agg.down
			acc.up += agg.up
			acc.observeCategory(agg.category, agg.bytes())
			if agg.isNew && agg.key.Service != "" && !newSeen[agg.key.Service] {
				newSeen[agg.key.Service] = true
				sess.NewServices = append(sess.NewServices, agg.key.Service)
			}
		}
	}
	sess.Bytes = sess.Down + sess.Up
	sess.Direction = directionHint(sess.Up, sess.Down)
	sortTimelineAggs(order)

	// Leader and SDK list come from the full list, before the display cap: the
	// thirteenth ad SDK still proves an app was running.
	for _, acc := range order {
		if acc.key.Unnamed || !isSDKRole(acc.key.Role) || acc.key.Service == "" {
			continue
		}
		sess.SDK = append(sess.SDK, acc.key.Service)
	}
	if leader := pickTimelineLeader(order); leader != nil {
		row := timelineSessionService(leader)
		sess.Leader = &row
	}

	limit := min(len(order), timelineSessionServices)
	sess.Services = make([]apiTimelineSessionService, 0, limit)
	for _, acc := range order[:limit] {
		sess.Services = append(sess.Services, timelineSessionService(acc))
	}
	return sess
}

func timelineSessionService(a *timelineServiceAgg) apiTimelineSessionService {
	return apiTimelineSessionService{
		Service: a.key.Service, Role: a.key.Role, Category: a.category,
		Bytes: a.bytes(), Down: a.down, Up: a.up,
		Direction: directionHint(a.up, a.down),
	}
}

// pickTimelineLeader answers "what was this stretch mostly about". Named
// leader-capable services win first; a bare-IP aggregate may lead only when no
// named candidate qualifies (org-labeled QUIC is still better than silence);
// an ad-SDK-only stretch gets no leader at all, because naming one would assert
// something the evidence does not show. `order` must be bytes-desc sorted.
func pickTimelineLeader(order []*timelineServiceAgg) *timelineServiceAgg {
	for _, acc := range order {
		if acc.key.Unnamed || acc.key.Service == "" {
			continue
		}
		if !isLeaderRole(acc.key.Role) || timelineInfraCategories[acc.category] {
			continue
		}
		return acc
	}
	for _, acc := range order {
		if acc.key.Unnamed && acc.key.Service != "" {
			return acc
		}
	}
	return nil
}

// handleClientTimeline serves GET /api/clients/{name}/timeline. Dispatched from
// handleClientDetail's sub-path switch, like /minute.
func (s *webServer) handleClientTimeline(w http.ResponseWriter, r *http.Request, name string) {
	ctx := r.Context()
	from, to := detailWindowFromRequest(r, timelineDefaultWindow)
	gap := parseTimelineGap(r)
	resp := apiTimeline{
		Name:       name,
		From:       from.Unix(),
		To:         to.Unix(),
		GapSeconds: int(gap / time.Second),
		LoggerOK:   s.loggerHealthy(),
		DBOK:       true,
	}
	fromMin := from.Unix() / 60
	toMin := to.Unix() / 60

	db, dbErr := openRollupReadOnly(s.rollupPath)
	if dbErr != nil {
		db = nil
	}
	// A window wider than the cap still reports db_ok honestly (the open above is
	// the probe) but renders nothing: null minutes, null sessions, a note.
	if n := toMin - fromMin + 1; n <= 0 || n > timelineMaxMinutes {
		if db != nil {
			_ = db.Close()
		}
		if dbErr != nil {
			logRateLimited("rollup", "wgflow web: rollup read: %v", dbErr)
			resp.DBOK = false
		}
		resp.Note = fmt.Sprintf("window is %d minutes; the timeline renders at most %d", n, timelineMaxMinutes)
		writeJSON(w, resp)
		return
	}

	// Close the rollup before the JSONL scans: they must not hold the shared
	// bbolt flock while the capture process wants to write.
	byMinute, flowsErr := s.clientFlowsByMinute(ctx, db, name, from, to)
	if db != nil {
		_ = db.Close()
	}
	if ctx.Err() != nil {
		return
	}
	if dbErr == nil {
		dbErr = flowsErr
	}
	if dbErr != nil {
		logRateLimited("rollup", "wgflow web: rollup read: %v", dbErr)
		resp.DBOK = false
		// Never let a rollup outage read as a quiet client.
		resp.Note = "rollup unavailable: per-minute bytes are missing from this timeline"
	}

	attrs, err := s.flowAttributionsContext(ctx, from, to, name)
	if err != nil {
		return
	}
	base, err := s.timelineBaselineContext(ctx, from, to, name)
	if err != nil {
		return
	}
	if ctx.Err() != nil {
		return
	}

	mins := timelineMinutes(byMinute, attrs, base, fromMin, toMin)
	resp.Minutes = timelineAPIMinutes(mins)
	resp.Sessions = timelineSessions(mins, gap)
	writeJSON(w, resp)
}
