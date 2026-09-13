package main

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// orgPrefixes maps well-known network prefixes (IPv4+IPv6) to the organization
// operating them. Accuracy target is "whose backbone is this", not per-service
// attribution: it names the ~90% of bare-IP traffic (nested tunnels, QUIC
// without SNI, proxies) that would otherwise render as an anonymous address.
// Sorted lookup is unnecessary at this size — orgForIP does one linear pass
// with zero allocations and keeps the most specific (longest) match.
var orgPrefixes = []struct {
	prefix netip.Prefix
	org    string
}{
	// Cloudflare (CDN edges + WARP egress ranges seen in production).
	{netip.MustParsePrefix("104.16.0.0/13"), "Cloudflare"},
	{netip.MustParsePrefix("104.24.0.0/14"), "Cloudflare"},
	{netip.MustParsePrefix("104.28.0.0/14"), "Cloudflare"}, // WARP egress (104.28-31)
	{netip.MustParsePrefix("162.158.0.0/15"), "Cloudflare"},
	{netip.MustParsePrefix("172.64.0.0/13"), "Cloudflare"},
	{netip.MustParsePrefix("188.114.96.0/20"), "Cloudflare"},
	{netip.MustParsePrefix("2606:4700::/32"), "Cloudflare"},
	// Meta.
	{netip.MustParsePrefix("31.13.24.0/21"), "Meta"},
	{netip.MustParsePrefix("31.13.64.0/18"), "Meta"},
	{netip.MustParsePrefix("57.144.0.0/14"), "Meta"},
	{netip.MustParsePrefix("157.240.0.0/16"), "Meta"},
	{netip.MustParsePrefix("179.60.192.0/22"), "Meta"},
	{netip.MustParsePrefix("2a03:2880::/29"), "Meta"},
	// Google (consumer edges) and Google Cloud customer ranges, kept apart:
	// GCP traffic is some tenant's, not Google's own services.
	{netip.MustParsePrefix("74.125.0.0/16"), "Google"},
	{netip.MustParsePrefix("142.250.0.0/15"), "Google"},
	{netip.MustParsePrefix("172.217.0.0/16"), "Google"},
	{netip.MustParsePrefix("172.253.0.0/16"), "Google"},
	{netip.MustParsePrefix("216.58.192.0/19"), "Google"},
	{netip.MustParsePrefix("2a00:1450::/32"), "Google"},
	{netip.MustParsePrefix("34.64.0.0/10"), "Google Cloud"},
	{netip.MustParsePrefix("35.184.0.0/13"), "Google Cloud"},
	// Apple owns 17/8 outright.
	{netip.MustParsePrefix("17.0.0.0/8"), "Apple"},
	// Amazon: CloudFront edge ranges first (more specific), then general AWS.
	{netip.MustParsePrefix("13.32.0.0/15"), "Amazon CloudFront"},
	{netip.MustParsePrefix("18.64.0.0/14"), "Amazon CloudFront"},
	{netip.MustParsePrefix("52.84.0.0/15"), "Amazon CloudFront"},
	{netip.MustParsePrefix("99.86.0.0/16"), "Amazon CloudFront"},
	{netip.MustParsePrefix("3.0.0.0/9"), "Amazon AWS"},
	{netip.MustParsePrefix("3.128.0.0/9"), "Amazon AWS"}, // covers the 3.17x CloudFront edges too
	{netip.MustParsePrefix("18.128.0.0/9"), "Amazon AWS"},
	// Akamai.
	{netip.MustParsePrefix("2.16.0.0/13"), "Akamai"},
	{netip.MustParsePrefix("23.32.0.0/11"), "Akamai"},
	{netip.MustParsePrefix("104.64.0.0/10"), "Akamai"},
	// Microsoft (Azure + O365 backbones).
	{netip.MustParsePrefix("13.64.0.0/11"), "Microsoft"},
	{netip.MustParsePrefix("20.0.0.0/11"), "Microsoft"},
	{netip.MustParsePrefix("20.192.0.0/10"), "Microsoft"},
	{netip.MustParsePrefix("40.74.0.0/15"), "Microsoft"},
	{netip.MustParsePrefix("52.96.0.0/12"), "Microsoft"},
	// Yandex.
	{netip.MustParsePrefix("5.255.192.0/18"), "Yandex"},
	{netip.MustParsePrefix("37.140.128.0/18"), "Yandex"},
	{netip.MustParsePrefix("77.88.0.0/18"), "Yandex"},
	{netip.MustParsePrefix("87.250.224.0/19"), "Yandex"},
	{netip.MustParsePrefix("93.158.128.0/18"), "Yandex"},
	{netip.MustParsePrefix("213.180.192.0/19"), "Yandex"},
	{netip.MustParsePrefix("2a02:6b8::/32"), "Yandex"},
	// VK.
	{netip.MustParsePrefix("87.240.128.0/18"), "VK"},
	{netip.MustParsePrefix("95.142.192.0/20"), "VK"},
	{netip.MustParsePrefix("2a00:bdc0::/32"), "VK"},
	// Telegram (moved here from the old enrichTarget string-prefix checks;
	// 149.154/16 and 91.108/16 are broader than Telegram's exact /20-/22
	// allocations but backbone-level accuracy is the contract of this table).
	{netip.MustParsePrefix("91.105.192.0/23"), "Telegram"},
	{netip.MustParsePrefix("91.108.0.0/16"), "Telegram"},
	{netip.MustParsePrefix("149.154.160.0/20"), "Telegram"},
	// Hosting providers commonly seen behind nested tunnels/proxies.
	{netip.MustParsePrefix("5.9.0.0/16"), "Hetzner"},
	{netip.MustParsePrefix("88.198.0.0/16"), "Hetzner"},
	{netip.MustParsePrefix("95.216.0.0/15"), "Hetzner"},
	{netip.MustParsePrefix("51.68.0.0/14"), "OVH"},
	{netip.MustParsePrefix("145.239.0.0/16"), "OVH"},
}

// orgForIP names the organization operating ip's network, or "" when the IP is
// not in the builtin table. One linear pass over ~50 prefixes, no allocations;
// the longest (most specific) matching prefix wins. Deliberately builtin-only:
// categorize calls this on the capture path, where an mmdb lookup per flow
// would be an unbounded new cost.
func orgForIP(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	addr = addr.Unmap()
	org := ""
	best := -1
	for _, e := range orgPrefixes {
		if e.prefix.Bits() > best && e.prefix.Contains(addr) {
			best = e.prefix.Bits()
			org = e.org
		}
	}
	return org
}

// ipOrgResolver names the organization behind an IP from an external source
// (an ASN database). It is only consulted after the builtin prefix table
// misses, and only on the enrich chain (web/report layer) — never per packet.
type ipOrgResolver interface {
	OrgForIP(addr netip.Addr) string
}

// ipOrgFallback is installed once at startup (see the web command's -asn-db
// flag) before any requests are served; nil means builtin table only.
var ipOrgFallback ipOrgResolver

func setIPOrgResolver(r ipOrgResolver) { ipOrgFallback = r }

// orgForIPEnriched is the full org chain: builtin prefix table first, then the
// optional ASN database.
func orgForIPEnriched(ip string) string {
	if org := orgForIP(ip); org != "" {
		return org
	}
	if ipOrgFallback == nil {
		return ""
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	return ipOrgFallback.OrgForIP(addr.Unmap())
}

func categorize(target, remoteIP, proto string, port uint16) string {
	t := strings.ToLower(target)
	ip := remoteIP
	if net.ParseIP(t) != nil {
		ip = t
		t = ""
	}
	// A bare IP carries no domain evidence, so the honest port heuristics
	// (STUN, DoT, nested tunnels) outrank the "whose address range is this"
	// guesses in the switch below: WARP to a Cloudflare IP is a proxy, DoT to
	// a Yandex resolver is DNS — not "cloudflare"/"yandex" browsing.
	if t == "" {
		if cat := categorizeByPort(proto, port, ip); cat != "" {
			return cat
		}
	}
	// ipHint gates every IP test in the switch: an address-range guess is
	// evidence ONLY when there is no name. A named target used to inherit the
	// label of whatever network its packets crossed — upload.picsart.com on a
	// Cloudflare edge read as "cloudflare", which answers "whose backbone"
	// when the question was "what was the person doing". The org of a named
	// target's IP still reaches the reader as target_org, never as category.
	ipHint := ip
	if t != "" {
		ipHint = ""
		// A service rule that pins a category (ad/telemetry SDKs) outranks the
		// brand switch: ms.applovin.com is an ad SDK, not "an AppLovin site".
		if c := targetRuleCategory(t); c != "" {
			return c
		}
	}
	switch {
	// Before the apple case: mask*.icloud.com is iCloud Private Relay — a
	// proxy tunnel, not regular Apple service chatter.
	case isPrivateRelayName(t):
		return "proxy"
	case containsAny(t, "instagram", "fbcdn", "facebook", "whatsapp", "meta.com") || ipPrefix(ipHint, "57.144.", "157.240.", "31.13.", "163.70."):
		return "meta"
	case containsAny(t, "youtube", "googlevideo", "ytimg", "googleapis", "googleusercontent") || ipPrefix(ipHint, "142.250.", "142.251.", "172.217.", "173.194.", "74.125.", "216.239."):
		return "google"
	case containsAny(t, "yandex", "yastatic", "ya.ru", "strm.yandex", "appmetrica") || ipPrefix(ipHint, "87.250.", "213.180.", "37.9.", "37.140.", "5.45.", "5.255.", "77.88."):
		return "yandex"
	case containsAny(t, "icloud", "apple.com", "mzstatic", "itunes", "aaplimg") || ipPrefix(ipHint, "17."):
		return "apple"
	case containsAny(t, "telegram", "t.me") || ipPrefix(ipHint, "149.154.", "91.108.", "91.105."):
		return "telegram"
	case containsAny(t, "tiktok", "tiktokcdn", "tiktokv", "capcut", "capcutapi", "ibyteimg", "byteimg", "byteoversea", "snssdk", "muscdn", "pstatp") || ipPrefix(ipHint, "71.18."):
		return "bytedance"
	case containsAny(t, "vk.com", "vkontakte", "userapi.com", "vk-cdn", "mycdn.me", "vkuser", "vkgroup", "vk.me") || ipPrefix(ipHint, "87.240.", "93.186.", "95.142.", "95.213."):
		return "vk"
	case containsAny(t, "netflix", "nflxvideo", "nflximg", "nflxext", "nflxso"):
		return "netflix"
	case containsAny(t, "spotify", "scdn.co", "pscdn.co", "spotifycdn"):
		return "spotify"
	case containsAny(t, "twitch", "ttvnw.net", "jtvnw.net", "live-video.net"):
		return "twitch"
	case containsAny(t, "discord", "discordapp"):
		return "discord"
	case containsAny(t, "microsoft", "windowsupdate", "office.com", "office365", "live.com", "outlook", "msedge", "bing.com", "azureedge", "msftncsi", "msftconnecttest", "skype"):
		return "microsoft"
	case containsAny(t, "wildberries"):
		return "wildberries"
	case containsAny(t, "fansly", "fbuddy"):
		return "fansly"
	case containsAny(t, "one.one.one.one") || ipHint == "1.1.1.1" || ipHint == "1.0.0.1":
		return "dns"
	case containsAny(t, "cloudflare", "workers.dev", "pages.dev") || ipPrefix(ipHint,
		"104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.",
		"104.24.", "104.25.", "104.26.", "104.27.", "104.28.", "104.29.", "104.30.", "104.31.",
		"162.158.", "162.159.", "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.",
		"172.70.", "172.71.", "188.114."):
		return "cloudflare"
	case containsAny(t, "cloudfront", "amazonaws", "awsstatic"):
		return "aws"
	case containsAny(t, "battle.net", "blizzard", "steam", "steampowered", "steamcontent", "epicgames", "riotgames", "xboxlive", "playstation"):
		return "games"
	case containsAny(t, "akamai", "akamaized", "fastly", "edgekey", "edgesuite", "llnwd", "cdn77", "jsdelivr", "stackpath"):
		return "cdn"
	case port == 6881 || (port >= 6881 && port <= 6999):
		return "p2p"
	default:
		// Named target that matched no domain rule: the port heuristics get the
		// last word before "other" (e.g. stun.example.org:3478 -> calls).
		if cat := categorizeByPort(proto, port, ip); cat != "" {
			return cat
		}
		return "other"
	}
}

// categoryForOrg maps a network-owner label (the org half of enrichTarget) to a
// category. It exists so a BARE IP with no name at all can still say something
// better than "other" — and only there: for a named target the org describes
// the road, not the destination, so the caller must not consult this. The org
// strings are the exact values orgPrefixes / orgForTargetName produce.
//
// "Google Cloud" deliberately maps to nothing: a GCP range carries some
// tenant's traffic, and labelling it "google" would invent a relationship with
// Google's own services that the evidence does not support.
func categoryForOrg(org string) string {
	switch org {
	case "Cloudflare":
		return "cloudflare"
	case "Amazon CloudFront", "Amazon AWS":
		return "aws"
	case "Akamai":
		return "cdn"
	case "Google":
		return "google"
	case "Meta":
		return "meta"
	case "Apple":
		return "apple"
	case "Yandex", "Yandex Storage":
		return "yandex"
	case "VK":
		return "vk"
	case "Telegram":
		return "telegram"
	case "Microsoft":
		return "microsoft"
	case "ByteDance/TikTok edge":
		return "bytedance"
	case "iCloud Private Relay":
		return "proxy"
	}
	return ""
}

// ipDerivedInfraCategories are the labels a NAMED target could only have got
// from its remote IP (D1: the old switch let ipPrefix clauses fire for named
// targets, and the result is frozen inside the rollup key for up to 7 days of
// detail history). The read-time recompute therefore replaces them even when
// the honest answer is "other" — a stale lie is worse than an admitted blank.
var ipDerivedInfraCategories = map[string]bool{"cloudflare": true, "aws": true, "cdn": true}

// isPrivateRelayName spots iCloud Private Relay SNIs (mask.icloud.com,
// mask-h2.icloud.com, mask-api.icloud.com).
func isPrivateRelayName(t string) bool {
	return (strings.HasPrefix(t, "mask.") || strings.HasPrefix(t, "mask-")) && strings.HasSuffix(t, ".icloud.com")
}

// categorizeByPort names traffic by well-known port when no domain rule fired.
// These are the honest labels for the "other ports" bucket observed in
// production: nested tunnels/proxies, STUN calls, APNs, encrypted DNS.
func categorizeByPort(proto string, port uint16, ip string) string {
	switch port {
	case 3478, 5349:
		return "calls" // STUN/TURN — voice/video call setup and media relay
	case 853:
		return "dns" // DNS over TLS/QUIC
	case 5223:
		if proto == "tcp" {
			return "apple" // Apple Push Notification service
		}
	case 1194:
		return "proxy" // OpenVPN (tcp and udp)
	}
	switch proto {
	case "tcp":
		switch port {
		case 1180, 12324: // nested SOCKS/VPN tunnels observed in production
			return "proxy"
		}
	case "udp":
		switch port {
		case 2408: // Cloudflare WARP MASQUE
			return "proxy"
		case 1701, 4500: // L2TP, IPsec NAT-T
			return "proxy"
		case 51820: // WireGuard-in-WireGuard
			return "proxy"
		}
		// Observed WARP pattern: high UDP ports 19300-19330 into Cloudflare
		// address space. The builtin table only — never the ASN DB — keeps
		// this safe on the capture hot path.
		if port >= 19300 && port <= 19330 && orgForIP(ip) == "Cloudflare" {
			return "proxy"
		}
	}
	return ""
}

// builtinTargetNames is the default IP -> display-hostname table used by
// enrichTarget (mostly CloudFront edges seen from this deployment). Keys are
// exact IPs or prefixes (trailing '.'). clients.yaml `target_names:` entries
// are merged on top — CDN edges rotate faster than this binary ships.
var builtinTargetNames = map[string]string{
	"3.173.161.68":  "server-3-173-161-68.ams56.r.cloudfront.net",
	"3.173.161.31":  "server-3-173-161-31.ams56.r.cloudfront.net",
	"3.173.161.86":  "server-3-173-161-86.ams56.r.cloudfront.net",
	"3.171.214.100": "server-3-171-214-100.fra50.r.cloudfront.net",
	"3.171.214.77":  "server-3-171-214-77.fra50.r.cloudfront.net",
	"18.239.36.50":  "server-18-239-36-50.ams58.r.cloudfront.net",
	"18.239.36.56":  "server-18-239-36-56.ams58.r.cloudfront.net",
	"99.86.12.89":   "server-99-86-12-89.ams54.r.cloudfront.net",
}

// activeTargetNames is the merged builtin+override view, swapped atomically
// under the mutex because loadAliasConfig may install overrides while other
// goroutines resolve names.
var targetNamesMu sync.RWMutex

var activeTargetNames = builtinTargetNames

// setTargetNameOverrides merges clients.yaml target_names on top of the
// builtin table. An empty value removes a builtin entry; nil restores pure
// defaults.
func setTargetNameOverrides(overrides map[string]string) {
	merged := make(map[string]string, len(builtinTargetNames)+len(overrides))
	for k, v := range builtinTargetNames {
		merged[k] = v
	}
	for k, v := range overrides {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" {
			continue
		}
		if v == "" {
			delete(merged, k)
			continue
		}
		merged[k] = v
	}
	targetNamesMu.Lock()
	activeTargetNames = merged
	targetNamesMu.Unlock()
}

// lookupTargetName resolves an IP against the merged table: exact key first,
// then the longest matching prefix key (keys ending with '.').
func lookupTargetName(ip string) (string, bool) {
	targetNamesMu.RLock()
	table := activeTargetNames
	targetNamesMu.RUnlock()
	if name, ok := table[ip]; ok {
		return name, true
	}
	bestLen := 0
	bestName := ""
	for k, v := range table {
		if strings.HasSuffix(k, ".") && strings.HasPrefix(ip, k) && len(k) > bestLen {
			bestLen, bestName = len(k), v
		}
	}
	return bestName, bestLen > 0
}

func enrichTarget(target, remoteIP, proto string, port uint16) (resolvedTarget, targetOrg string) {
	ip := target
	if net.ParseIP(ip) == nil {
		ip = remoteIP
	}
	if net.ParseIP(ip) == nil {
		return "", ""
	}
	// The configurable table wins over the coded heuristics below so an
	// operator can correct or extend attribution without a rebuild.
	if name, ok := lookupTargetName(ip); ok {
		return name, orgOrIPFallback(orgForTargetName(name), ip)
	}
	switch {
	case strings.HasPrefix(ip, "37.140.178."):
		if octet, ok := suffixIPv4Octet(ip, "37.140.178."); ok {
			return "s" + octet + "nrg.storage.yandex.net", "Yandex Storage"
		}
	case strings.HasPrefix(ip, "5.255.221."):
		if octet, ok := suffixIPv4Octet(ip, "5.255.221."); ok {
			return "s" + octet + "klg.storage.yandex.net", "Yandex Storage"
		}
	case strings.HasPrefix(ip, "71.18.251."):
		return "", "ByteDance/TikTok edge"
	case ip == "45.140.39.182" || ip == "45.157.182.3" || ip == "64.72.204.203" || ip == "171.22.220.242" || ip == "209.200.248.83":
		return "", "unattributed infra"
	}
	if proto == "tcp" && port == 443 {
		if name := reverseTargetName(ip); name != "" {
			return name, orgOrIPFallback(orgForTargetName(name), ip)
		}
		if ipPrefix(ip, "3.171.214.", "3.173.161.", "18.239.36.", "99.86.12.") {
			return "", "Amazon CloudFront"
		}
	}
	// No PTR and no hand-curated match: fall back to the network-owner table
	// (Telegram/Cloudflare/Hetzner/...), then the optional ASN database, so
	// nested tunnels and QUIC-without-SNI at least say whose backbone they use.
	if org := orgForIPEnriched(ip); org != "" {
		return "", org
	}
	if proto == "tcp" && port == 12324 {
		return "", "unattributed tcp/12324"
	}
	return "", ""
}

// orgOrIPFallback keeps a name-derived org when there is one and otherwise
// falls back to the network-owner chain (builtin table, then ASN DB).
func orgOrIPFallback(org, ip string) string {
	if org != "" {
		return org
	}
	return orgForIPEnriched(ip)
}

type reverseDNSResult struct {
	name      string
	expiresAt time.Time
}

// reverseDNSCacheMax bounds the PTR cache: the key space is every remote IP
// ever seen, so without a cap a port scan grows it forever.
const reverseDNSCacheMax = 4096

var reverseDNSCache = struct {
	sync.Mutex
	m map[string]reverseDNSResult
}{m: map[string]reverseDNSResult{}}

// reverseDNSLookup returns the cached PTR result for ip, expired or not — the
// caller decides whether a stale entry is still usable (stale-while-revalidate
// in the web layer) or must be refreshed.
func reverseDNSLookup(ip string) (reverseDNSResult, bool) {
	reverseDNSCache.Lock()
	r, ok := reverseDNSCache.m[ip]
	reverseDNSCache.Unlock()
	return r, ok
}

// reverseDNSStore inserts a result, enforcing the cap when adding a new key.
// Expired entries go first; if the cache is full of live entries drop
// arbitrary ones — a re-lookup is cheap next time the IP shows up.
func reverseDNSStore(ip string, r reverseDNSResult) {
	now := time.Now()
	reverseDNSCache.Lock()
	if _, exists := reverseDNSCache.m[ip]; !exists && len(reverseDNSCache.m) >= reverseDNSCacheMax {
		for k, old := range reverseDNSCache.m {
			if !now.Before(old.expiresAt) {
				delete(reverseDNSCache.m, k)
			}
		}
		for k := range reverseDNSCache.m {
			if len(reverseDNSCache.m) < reverseDNSCacheMax {
				break
			}
			delete(reverseDNSCache.m, k)
		}
	}
	reverseDNSCache.m[ip] = r
	reverseDNSCache.Unlock()
}

func reverseDNSDelete(ip string) {
	reverseDNSCache.Lock()
	delete(reverseDNSCache.m, ip)
	reverseDNSCache.Unlock()
}

func reverseTargetName(ip string) string {
	now := time.Now()
	if r, ok := reverseDNSLookup(ip); ok && now.Before(r.expiresAt) {
		return r.name
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	name := ""
	if err == nil && len(names) > 0 {
		name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(names[0])), ".")
	}
	ttl := 5 * time.Minute
	if name != "" {
		ttl = 12 * time.Hour
	}
	reverseDNSStore(ip, reverseDNSResult{name: name, expiresAt: now.Add(ttl)})
	return name
}

func orgForTargetName(name string) string {
	n := strings.ToLower(name)
	switch {
	case isPrivateRelayName(n):
		return "iCloud Private Relay"
	case strings.Contains(n, "cloudfront"):
		return "Amazon CloudFront"
	case strings.Contains(n, "storage.yandex") || strings.Contains(n, "yandex"):
		return "Yandex"
	case strings.Contains(n, "telegram"):
		return "Telegram"
	case containsAny(n, "bytedance", "tiktok", "capcut", "ibyteimg", "byteimg"):
		return "ByteDance/TikTok edge"
	default:
		return ""
	}
}

func suffixIPv4Octet(ip, prefix string) (string, bool) {
	s, ok := strings.CutPrefix(ip, prefix)
	if !ok || strings.Contains(s, ".") {
		return "", false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 255 {
		return "", false
	}
	return s, true
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func ipPrefix(ip string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(ip, p) {
			return true
		}
	}
	return false
}
