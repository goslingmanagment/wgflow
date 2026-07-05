package main

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

func categorize(target, remoteIP, proto string, port uint16) string {
	t := strings.ToLower(target)
	ip := remoteIP
	if net.ParseIP(t) != nil {
		ip = t
		t = ""
	}
	switch {
	case containsAny(t, "instagram", "fbcdn", "facebook", "whatsapp", "meta.com") || ipPrefix(ip, "57.144.", "157.240.", "31.13.", "163.70."):
		return "meta"
	case containsAny(t, "youtube", "googlevideo", "ytimg", "googleapis", "googleusercontent") || ipPrefix(ip, "142.250.", "142.251.", "172.217.", "173.194.", "74.125.", "216.239."):
		return "google"
	case containsAny(t, "yandex", "yastatic", "ya.ru", "strm.yandex", "appmetrica") || ipPrefix(ip, "87.250.", "213.180.", "37.9.", "37.140.", "5.45.", "5.255.", "77.88."):
		return "yandex"
	case containsAny(t, "icloud", "apple.com", "mzstatic", "itunes", "aaplimg") || ipPrefix(ip, "17."):
		return "apple"
	case containsAny(t, "telegram", "t.me") || ipPrefix(ip, "149.154.", "91.108.", "91.105."):
		return "telegram"
	case containsAny(t, "tiktok", "tiktokcdn", "tiktokv", "capcut", "capcutapi", "ibyteimg", "byteimg", "byteoversea", "snssdk", "muscdn", "pstatp") || ipPrefix(ip, "71.18."):
		return "bytedance"
	case containsAny(t, "vk.com", "vkontakte", "userapi.com", "vk-cdn", "mycdn.me", "vkuser", "vkgroup", "vk.me") || ipPrefix(ip, "87.240.", "93.186.", "95.142.", "95.213."):
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
	case containsAny(t, "one.one.one.one") || ip == "1.1.1.1" || ip == "1.0.0.1":
		return "dns"
	case containsAny(t, "cloudflare", "workers.dev", "pages.dev") || ipPrefix(ip,
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
		return "other"
	}
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
		return name, orgForTargetName(name)
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
	case ipPrefix(ip, "149.154.", "91.108.", "91.105."):
		return "", "Telegram network"
	case ip == "45.140.39.182" || ip == "45.157.182.3" || ip == "64.72.204.203" || ip == "171.22.220.242" || ip == "209.200.248.83":
		return "", "unattributed infra"
	}
	if proto == "tcp" && port == 443 {
		if name := reverseTargetName(ip); name != "" {
			return name, orgForTargetName(name)
		}
		if ipPrefix(ip, "3.171.214.", "3.173.161.", "18.239.36.", "99.86.12.") {
			return "", "Amazon CloudFront"
		}
	}
	if proto == "tcp" && port == 12324 {
		return "", "unattributed tcp/12324"
	}
	return "", ""
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
	case strings.Contains(n, "cloudfront"):
		return "Amazon CloudFront"
	case strings.Contains(n, "storage.yandex") || strings.Contains(n, "yandex"):
		return "Yandex"
	case strings.Contains(n, "telegram"):
		return "Telegram network"
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
