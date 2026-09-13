package main

import (
	"net"
	"strings"
	"sync"

	"golang.org/x/net/publicsuffix"
)

// Service + role attribution for NAMED targets ("who is the client talking to,
// and what kind of endpoint is it"). This layer is READ-TIME ONLY: nothing here
// is stored in the rollup, whose category is frozen inside the bbolt key, so a
// rule change re-labels all retained history the moment the panel restarts.
//
// Two axes, deliberately distinct from `category` (which mixes "whose backbone"
// with "which brand"):
//
//   - service: WHO — a human label ("AppLovin", "Picsart") or, by default, the
//     registrable domain (eTLD+1, "picsart.com"), so an unknown host names
//     itself instead of drowning in "other";
//   - role: WHAT KIND — ads, telemetry, push, cdn, media, sync, proxy, dns.
//     A role is assigned only where the hostname is unambiguous
//     (ms.applovin.com is only ever the AppLovin SDK) and never asserts human
//     intent; the verdict engine may cite it as a reason, never as proof.
//
// Rules are a suffix table (the rule for "applovin.com" matches the apex and
// every label beneath it; the longest suffix wins), extended per deployment
// from clients.yaml `services:` — the same pattern as `target_names`.

const (
	roleAds       = "ads"       // ad-network SDK / ad serving
	roleTelemetry = "telemetry" // analytics, crash reporting, attribution SDKs
	rolePush      = "push"      // push-notification transports
	roleCDN       = "cdn"       // static-asset edges of a known brand
	roleMedia     = "media"     // audio/video streaming payload hosts
	roleSync      = "sync"      // cloud backup / photo / drive sync
	roleProxy     = "proxy"     // relays and tunnels (Private Relay, WARP)
	roleDNS       = "dns"       // encrypted-DNS resolvers
)

// serviceRule describes one hostname suffix. Category, when set, is the coarse
// rollup category categorize() assigns at capture time (e.g. "ads") so the Mix,
// the board and the verdict engine see the role without per-target rows.
type serviceRule struct {
	Service  string `yaml:"service"`
	Role     string `yaml:"role"`
	Category string `yaml:"category"`
}

// isSDKRole is the "an app with this SDK is running" signal: ad and telemetry
// SDKs only phone home from a launched app, which is why the verdict engine
// treats them as foreground evidence (hedged).
func isSDKRole(role string) bool {
	return role == roleAds || role == roleTelemetry
}

// isLeaderRole reports whether a service with this role can headline an
// activity session. Infrastructure roles never lead: "the person used
// Cloudflare" is not an answer to "what were they doing".
func isLeaderRole(role string) bool {
	switch role {
	case roleAds, roleTelemetry, rolePush, roleCDN, roleSync, roleProxy, roleDNS:
		return false
	}
	return true
}

// builtinServiceRules — keyed by domain suffix. Keep entries unambiguous: a
// suffix that serves both a consumer product and an SDK (graph.facebook.com,
// googleapis.com) gets no role here; be specific instead (the SDK subdomain).
var builtinServiceRules = map[string]serviceRule{
	// Ad networks / mediation.
	"applovin.com":          {Service: "AppLovin", Role: roleAds, Category: "ads"},
	"vungle.com":            {Service: "Vungle", Role: roleAds, Category: "ads"},
	"unityads.unity3d.com":  {Service: "Unity Ads", Role: roleAds, Category: "ads"},
	"ironsrc.com":           {Service: "ironSource", Role: roleAds, Category: "ads"},
	"chartboost.com":        {Service: "Chartboost", Role: roleAds, Category: "ads"},
	"inmobi.com":            {Service: "InMobi", Role: roleAds, Category: "ads"},
	"mintegral.com":         {Service: "Mintegral", Role: roleAds, Category: "ads"},
	"pangle.io":             {Service: "Pangle", Role: roleAds, Category: "ads"},
	"adcolony.com":          {Service: "AdColony", Role: roleAds, Category: "ads"},
	"moloco.com":            {Service: "Moloco", Role: roleAds, Category: "ads"},
	"liftoff.io":            {Service: "Liftoff", Role: roleAds, Category: "ads"},
	"fyber.com":             {Service: "Fyber", Role: roleAds, Category: "ads"},
	"bidmachine.io":         {Service: "BidMachine", Role: roleAds, Category: "ads"},
	"smaato.net":            {Service: "Smaato", Role: roleAds, Category: "ads"},
	"pubmatic.com":          {Service: "PubMatic", Role: roleAds, Category: "ads"},
	"doubleclick.net":       {Service: "Google Ads", Role: roleAds, Category: "ads"},
	"googlesyndication.com": {Service: "Google Ads", Role: roleAds, Category: "ads"},
	"googleadservices.com":  {Service: "Google Ads", Role: roleAds, Category: "ads"},
	"admob.com":             {Service: "AdMob", Role: roleAds, Category: "ads"},
	"an.yandex.ru":          {Service: "Yandex Ads", Role: roleAds, Category: "ads"},
	"yandexadexchange.net":  {Service: "Yandex Ads", Role: roleAds, Category: "ads"},
	"adfox.ru":              {Service: "AdFox", Role: roleAds, Category: "ads"},
	"mytarget.mail.ru":      {Service: "myTarget", Role: roleAds, Category: "ads"},
	"ads.tiktok.com":        {Service: "TikTok Ads", Role: roleAds, Category: "ads"},
	"criteo.com":            {Service: "Criteo", Role: roleAds, Category: "ads"},
	"taboola.com":           {Service: "Taboola", Role: roleAds, Category: "ads"},
	"outbrain.com":          {Service: "Outbrain", Role: roleAds, Category: "ads"},
	// Attribution / analytics / crash reporting.
	"adjust.com":                           {Service: "Adjust", Role: roleTelemetry, Category: "ads"},
	"appsflyer.com":                        {Service: "AppsFlyer", Role: roleTelemetry, Category: "ads"},
	"branch.io":                            {Service: "Branch", Role: roleTelemetry, Category: "ads"},
	"kochava.com":                          {Service: "Kochava", Role: roleTelemetry, Category: "ads"},
	"singular.net":                         {Service: "Singular", Role: roleTelemetry, Category: "ads"},
	"amplitude.com":                        {Service: "Amplitude", Role: roleTelemetry, Category: "ads"},
	"mixpanel.com":                         {Service: "Mixpanel", Role: roleTelemetry, Category: "ads"},
	"segment.io":                           {Service: "Segment", Role: roleTelemetry, Category: "ads"},
	"sentry.io":                            {Service: "Sentry", Role: roleTelemetry, Category: "ads"},
	"bugsnag.com":                          {Service: "Bugsnag", Role: roleTelemetry, Category: "ads"},
	"app-measurement.com":                  {Service: "Firebase Analytics", Role: roleTelemetry, Category: "ads"},
	"firebaselogging-pa.googleapis.com":    {Service: "Firebase", Role: roleTelemetry, Category: "ads"},
	"firebaseinstallations.googleapis.com": {Service: "Firebase", Role: roleTelemetry, Category: "ads"},
	"firebaseremoteconfig.googleapis.com":  {Service: "Firebase", Role: roleTelemetry, Category: "ads"},
	"crashlyticsreports-pa.googleapis.com": {Service: "Crashlytics", Role: roleTelemetry, Category: "ads"},
	"google-analytics.com":                 {Service: "Google Analytics", Role: roleTelemetry, Category: "ads"},
	"mc.yandex.ru":                         {Service: "Yandex Metrica", Role: roleTelemetry, Category: "ads"},
	"appmetrica.yandex.net":                {Service: "AppMetrica", Role: roleTelemetry, Category: "ads"},
	"appmetrica.yandex.com":                {Service: "AppMetrica", Role: roleTelemetry, Category: "ads"},
	"analytics.tiktok.com":                 {Service: "TikTok Analytics", Role: roleTelemetry, Category: "ads"},
	"business-api.tiktok.com":              {Service: "TikTok Analytics", Role: roleTelemetry, Category: "ads"},
	// Push transports.
	"push.apple.com":            {Service: "Apple Push", Role: rolePush},
	"mtalk.google.com":          {Service: "Google Push (FCM)", Role: rolePush},
	"fcm.googleapis.com":        {Service: "Google Push (FCM)", Role: rolePush},
	"push.services.mozilla.com": {Service: "Mozilla Push", Role: rolePush},
	"notify.windows.com":        {Service: "Windows Push", Role: rolePush},
	"wns.windows.com":           {Service: "Windows Push", Role: rolePush},
	// Streaming payload hosts.
	"googlevideo.com":  {Service: "YouTube", Role: roleMedia},
	"nflxvideo.net":    {Service: "Netflix", Role: roleMedia},
	"ttvnw.net":        {Service: "Twitch", Role: roleMedia},
	"tiktokcdn.com":    {Service: "TikTok", Role: roleMedia},
	"tiktokcdn-us.com": {Service: "TikTok", Role: roleMedia},
	"scdn.co":          {Service: "Spotify", Role: roleMedia},
	"strm.yandex.net":  {Service: "Yandex Music/Video", Role: roleMedia},
	"vkuservideo.net":  {Service: "VK Video", Role: roleMedia},
	"vkuseraudio.net":  {Service: "VK Music", Role: roleMedia},
	// Static edges of known brands.
	"fbcdn.net":             {Service: "Instagram/Facebook", Role: roleCDN},
	"cdninstagram.com":      {Service: "Instagram", Role: roleCDN},
	"ytimg.com":             {Service: "YouTube", Role: roleCDN},
	"mzstatic.com":          {Service: "Apple", Role: roleCDN},
	"gstatic.com":           {Service: "Google", Role: roleCDN},
	"googleusercontent.com": {Service: "Google", Role: roleCDN},
	"yastatic.net":          {Service: "Yandex", Role: roleCDN},
	"userapi.com":           {Service: "VK", Role: roleCDN},
	"akamaized.net":         {Service: "Akamai", Role: roleCDN},
	"akamaihd.net":          {Service: "Akamai", Role: roleCDN},
	"cloudfront.net":        {Service: "CloudFront", Role: roleCDN},
	// Cloud sync / backup.
	"icloud-content.com":     {Service: "iCloud", Role: roleSync},
	"icloud.com":             {Service: "iCloud"},
	"storage.yandex.net":     {Service: "Yandex Disk", Role: roleSync},
	"disk.yandex.ru":         {Service: "Yandex Disk", Role: roleSync},
	"dropbox.com":            {Service: "Dropbox", Role: roleSync},
	"dropboxusercontent.com": {Service: "Dropbox", Role: roleSync},
	"1drv.com":               {Service: "OneDrive", Role: roleSync},
	"onedrive.live.com":      {Service: "OneDrive", Role: roleSync},
	// Encrypted DNS resolvers.
	"dns.google":         {Service: "Google DNS", Role: roleDNS},
	"cloudflare-dns.com": {Service: "Cloudflare DNS", Role: roleDNS},
	"one.one.one.one":    {Service: "Cloudflare DNS", Role: roleDNS},
	"dns.apple.com":      {Service: "Apple DNS", Role: roleDNS},
	"dns.adguard.com":    {Service: "AdGuard DNS", Role: roleDNS},
	"adguard-dns.com":    {Service: "AdGuard DNS", Role: roleDNS},
	"dns.quad9.net":      {Service: "Quad9 DNS", Role: roleDNS},
	"nextdns.io":         {Service: "NextDNS", Role: roleDNS},
	"doh.opendns.com":    {Service: "OpenDNS", Role: roleDNS},
	// Consumer brands whose registrable domain reads badly on its own.
	"whatsapp.net":     {Service: "WhatsApp"},
	"whatsapp.com":     {Service: "WhatsApp"},
	"instagram.com":    {Service: "Instagram"},
	"facebook.com":     {Service: "Facebook"},
	"t.me":             {Service: "Telegram"},
	"telegram.org":     {Service: "Telegram"},
	"apple.com":        {Service: "Apple"},
	"youtube.com":      {Service: "YouTube"},
	"google.com":       {Service: "Google"},
	"googleapis.com":   {Service: "Google APIs"},
	"yandex.ru":        {Service: "Yandex"},
	"yandex.net":       {Service: "Yandex"},
	"vk.com":           {Service: "VK"},
	"vk.me":            {Service: "VK"},
	"tiktok.com":       {Service: "TikTok"},
	"tiktokv.com":      {Service: "TikTok"},
	"fansly.com":       {Service: "Fansly"},
	"onlyfans.com":     {Service: "OnlyFans"},
	"wildberries.ru":   {Service: "Wildberries"},
	"ozon.ru":          {Service: "Ozon"},
	"apps.apple.com":   {Service: "App Store"},
	"itunes.apple.com": {Service: "App Store"},
}

// activeServiceRules is the merged builtin+override view, swapped atomically
// under the mutex because loadAliasConfig may install overrides while request
// goroutines resolve names (the same discipline as activeTargetNames).
var (
	serviceRulesMu     sync.RWMutex
	activeServiceRules = builtinServiceRules
)

// setServiceRuleOverrides merges clients.yaml `services:` on top of the builtin
// table. An all-empty rule removes a builtin entry; nil restores pure defaults.
func setServiceRuleOverrides(overrides map[string]serviceRule) {
	merged := make(map[string]serviceRule, len(builtinServiceRules)+len(overrides))
	for k, v := range builtinServiceRules {
		merged[k] = v
	}
	for k, v := range overrides {
		k = normalizeHost(k)
		if k == "" {
			continue
		}
		v.Service = strings.TrimSpace(v.Service)
		v.Role = strings.ToLower(strings.TrimSpace(v.Role))
		v.Category = strings.ToLower(strings.TrimSpace(v.Category))
		if v == (serviceRule{}) {
			delete(merged, k)
			continue
		}
		merged[k] = v
	}
	serviceRulesMu.Lock()
	activeServiceRules = merged
	serviceRulesMu.Unlock()
}

// normalizeHost lowercases, trims whitespace and the trailing dot, and strips a
// leading '.' so ".example.com" and "example.com" name the same suffix.
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	h = strings.TrimPrefix(h, ".")
	return h
}

// lookupServiceRule finds the most specific rule for host: the host itself,
// then each parent suffix. Bare IPs never match.
func lookupServiceRule(host string) (serviceRule, bool) {
	h := normalizeHost(host)
	if h == "" || net.ParseIP(h) != nil {
		return serviceRule{}, false
	}
	serviceRulesMu.RLock()
	table := activeServiceRules
	serviceRulesMu.RUnlock()
	for {
		if r, ok := table[h]; ok {
			return r, true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			return serviceRule{}, false
		}
		h = h[i+1:]
	}
}

// registrableDomain returns the eTLD+1 of host ("upload.picsart.com" →
// "picsart.com", "foo.co.uk" → "foo.co.uk"). Falls back to the host itself
// when the public-suffix list cannot split it (a public suffix, a single label,
// an internal name). Empty for IPs and empty input.
func registrableDomain(host string) string {
	h := normalizeHost(host)
	if h == "" || net.ParseIP(h) != nil {
		return ""
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil {
		return d
	}
	return h
}

// targetService names WHO the client talks to: the rule's label if any, else
// the registrable domain. Empty for bare IPs (the caller has org/PTR for
// those) so the UI never invents a name.
func targetService(host string) string {
	if r, ok := lookupServiceRule(host); ok && r.Service != "" {
		return r.Service
	}
	return registrableDomain(host)
}

// targetRole names WHAT KIND of endpoint host is, or "" when the table has no
// unambiguous answer. Private Relay masks are a proxy regardless of the table.
func targetRole(host string) string {
	if isPrivateRelayName(normalizeHost(host)) {
		return roleProxy
	}
	if r, ok := lookupServiceRule(host); ok {
		return r.Role
	}
	return ""
}

// targetRuleCategory is the capture-time category a rule pins for host ("" when
// the rule is silent and the classic categorize switch decides).
func targetRuleCategory(host string) string {
	if r, ok := lookupServiceRule(host); ok {
		return r.Category
	}
	return ""
}

// Direction hint thresholds: below directionMinBytes the ratio is noise
// (handshakes, keepalives); above it a 3:1 skew is a real upload or download.
const (
	directionMinBytes = 256 << 10
	directionSkew     = 3
)

// directionHint reads a flow's byte skew: "upload" when the client sent ≥3× what
// it received (content going out — a photo upload, a backup), "download" for the
// mirror image (media coming in), "" for balanced chatter or tiny flows. The
// ~5 % GSO/GRO undercount does not move a 3:1 ratio.
func directionHint(up, down uint64) string {
	if up+down < directionMinBytes {
		return ""
	}
	switch {
	case up >= directionSkew*down:
		return "upload"
	case down >= directionSkew*up:
		return "download"
	}
	return ""
}
