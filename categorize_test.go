package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestTargetNameDefaults(t *testing.T) {
	setTargetNameOverrides(nil)
	name, ok := lookupTargetName("3.171.214.100")
	if !ok || name != "server-3-171-214-100.fra50.r.cloudfront.net" {
		t.Fatalf("builtin lookup = %q ok=%v", name, ok)
	}
	if _, ok := lookupTargetName("192.0.2.1"); ok {
		t.Fatal("unknown IP must not resolve")
	}
	resolved, org := enrichTarget("3.171.214.100", "", "tcp", 443)
	if resolved != "server-3-171-214-100.fra50.r.cloudfront.net" || org != "Amazon CloudFront" {
		t.Fatalf("enrichTarget = (%q, %q)", resolved, org)
	}
}

func TestTargetNameOverridesMergeWithDefaults(t *testing.T) {
	defer setTargetNameOverrides(nil)
	setTargetNameOverrides(map[string]string{
		"18.244.100.10": "server-18-244-100-10.fra60.r.cloudfront.net", // new exact entry
		"203.0.113.":    "edge.example.net",                            // prefix entry
		"203.0.113.7":   "special.example.net",                         // exact beats prefix
		"3.171.214.100": "corrected.cloudfront.example",                // override a builtin
		"99.86.12.89":   "",                                            // remove a builtin
	})

	// Untouched builtins survive the merge.
	if name, ok := lookupTargetName("18.239.36.50"); !ok || name != "server-18-239-36-50.ams58.r.cloudfront.net" {
		t.Fatalf("builtin after merge = %q ok=%v", name, ok)
	}
	if name, _ := lookupTargetName("18.244.100.10"); name != "server-18-244-100-10.fra60.r.cloudfront.net" {
		t.Fatalf("new exact = %q", name)
	}
	if name, _ := lookupTargetName("203.0.113.55"); name != "edge.example.net" {
		t.Fatalf("prefix match = %q", name)
	}
	if name, _ := lookupTargetName("203.0.113.7"); name != "special.example.net" {
		t.Fatalf("exact must beat prefix, got %q", name)
	}
	if name, _ := lookupTargetName("3.171.214.100"); name != "corrected.cloudfront.example" {
		t.Fatalf("override of builtin = %q", name)
	}
	if _, ok := lookupTargetName("99.86.12.89"); ok {
		t.Fatal("empty value must remove the builtin entry")
	}

	// enrichTarget derives the org from the (possibly overridden) name.
	if resolved, org := enrichTarget("203.0.113.55", "", "tcp", 443); resolved != "edge.example.net" || org != "" {
		t.Fatalf("enrichTarget prefix = (%q, %q)", resolved, org)
	}

	// Restoring defaults brings back removed builtins and drops overrides.
	setTargetNameOverrides(nil)
	if _, ok := lookupTargetName("99.86.12.89"); !ok {
		t.Fatal("reset must restore the builtin entry")
	}
	if _, ok := lookupTargetName("203.0.113.55"); ok {
		t.Fatal("reset must drop the override prefix")
	}
}

func TestLoadAliasConfigInstallsTargetNames(t *testing.T) {
	defer setTargetNameOverrides(nil)
	path := filepath.Join(t.TempDir(), "clients.yaml")
	cfg := `
people:
  - display: Diana
    devices: [diana-iphone]
target_names:
  "198.51.100.4": cache.example.org
  "18.239.36.50": ""
`
	if err := os.WriteFile(path, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}
	ac, err := loadAliasConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if ac.Person("diana-iphone") != "Diana" {
		t.Fatalf("people section must keep working, got %q", ac.Person("diana-iphone"))
	}
	if name, ok := lookupTargetName("198.51.100.4"); !ok || name != "cache.example.org" {
		t.Fatalf("yaml target name = %q ok=%v", name, ok)
	}
	if _, ok := lookupTargetName("18.239.36.50"); ok {
		t.Fatal("yaml empty value must remove the builtin entry")
	}
}

func TestOrgForIP(t *testing.T) {
	cases := []struct {
		ip   string
		want string
	}{
		{"104.29.153.158", "Cloudflare"}, // WARP egress range observed in production
		{"188.114.97.3", "Cloudflare"},
		{"2606:4700::6810:84e5", "Cloudflare"},
		{"157.240.20.35", "Meta"},
		{"57.144.110.1", "Meta"},
		{"2a03:2880:f003:c07::2", "Meta"},
		{"142.250.74.78", "Google"},
		{"2a00:1450:4010:c0e::5e", "Google"},
		{"34.120.10.5", "Google Cloud"},
		{"17.57.146.20", "Apple"},
		{"13.33.100.1", "Amazon CloudFront"},
		{"3.171.214.100", "Amazon AWS"},
		{"23.55.12.1", "Akamai"},
		{"20.201.28.151", "Microsoft"},
		{"77.88.55.88", "Yandex"},
		{"2a02:6b8::2:242", "Yandex"},
		{"87.240.190.72", "VK"},
		{"149.154.167.99", "Telegram"},
		{"91.108.56.130", "Telegram"},
		{"95.216.1.1", "Hetzner"},
		{"51.68.1.1", "OVH"},
		{"8.8.8.8", ""},    // present in DNS lore, absent from the table — must stay honest
		{"10.66.66.2", ""}, // private space never gets an org
		{"not-an-ip", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := orgForIP(tc.ip); got != tc.want {
			t.Errorf("orgForIP(%q) = %q, want %q", tc.ip, got, tc.want)
		}
	}
}

func TestEnrichTargetFallsBackToOrgTable(t *testing.T) {
	// Non-443 ports skip the PTR path entirely, so these exercise the pure
	// table fallback without touching the resolver.
	if resolved, org := enrichTarget("91.108.56.130", "", "tcp", 5222); resolved != "" || org != "Telegram" {
		t.Errorf("telegram fallback = (%q, %q), want (\"\", \"Telegram\")", resolved, org)
	}
	// The org table beats the "unattributed tcp/12324" stopgap when it knows
	// whose network the tunnel endpoint lives in.
	if _, org := enrichTarget("95.216.10.20", "", "tcp", 12324); org != "Hetzner" {
		t.Errorf("tcp/12324 to Hetzner = %q, want Hetzner", org)
	}
	if _, org := enrichTarget("198.51.100.99", "", "tcp", 12324); org != "unattributed tcp/12324" {
		t.Errorf("tcp/12324 to unknown = %q, want the stopgap label", org)
	}
	if _, org := enrichTarget("198.51.100.99", "", "udp", 4500); org != "" {
		t.Errorf("unknown IP must keep an empty org, got %q", org)
	}
}

// fakeIPOrgResolver stands in for the optional ASN .mmdb (generating a real
// micro-mmdb needs external tooling); the chain around it is what matters.
type fakeIPOrgResolver struct {
	answers map[string]string
	calls   int
}

func (f *fakeIPOrgResolver) OrgForIP(addr netip.Addr) string {
	f.calls++
	return f.answers[addr.String()]
}

func TestOrgChainPrefersBuiltinTableOverASNDB(t *testing.T) {
	defer setIPOrgResolver(nil)
	fake := &fakeIPOrgResolver{answers: map[string]string{
		"198.51.100.7":   "ExampleNet Ltd",
		"149.154.167.99": "WRONG-SHOULD-NOT-BE-ASKED",
	}}
	setIPOrgResolver(fake)

	// Builtin table wins; the ASN DB must not even be consulted.
	if org := orgForIPEnriched("149.154.167.99"); org != "Telegram" {
		t.Errorf("builtin hit = %q, want Telegram", org)
	}
	if fake.calls != 0 {
		t.Errorf("ASN DB consulted %d times on a builtin hit, want 0", fake.calls)
	}
	// Builtin miss falls through to the ASN DB.
	if org := orgForIPEnriched("198.51.100.7"); org != "ExampleNet Ltd" {
		t.Errorf("asn fallback = %q, want ExampleNet Ltd", org)
	}
	// Miss in both stays empty; garbage input never reaches the resolver.
	if org := orgForIPEnriched("203.0.113.200"); org != "" {
		t.Errorf("double miss = %q, want empty", org)
	}
	calls := fake.calls
	if org := orgForIPEnriched("not-an-ip"); org != "" || fake.calls != calls {
		t.Errorf("garbage input = %q (resolver calls %d -> %d)", org, calls, fake.calls)
	}

	// End to end through enrichTarget (non-443 port skips the PTR path).
	if resolved, org := enrichTarget("198.51.100.7", "", "udp", 2408); resolved != "" || org != "ExampleNet Ltd" {
		t.Errorf("enrichTarget via ASN DB = (%q, %q)", resolved, org)
	}

	// Without a resolver installed the chain degrades to the builtin table.
	setIPOrgResolver(nil)
	if org := orgForIPEnriched("198.51.100.7"); org != "" {
		t.Errorf("no resolver = %q, want empty", org)
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
		// A NAMED target never inherits the label of the network it crossed:
		// the remote IP only speaks when there is no name at all.
		{"static.example", "104.29.153.158", "other"},
		{"104.29.153.158", "104.29.153.158", "cloudflare"},
		{"upload.picsart.com", "104.29.153.158", "other"},
		{"upload.picsart.com", "17.1.1.1", "other"},
		// Ad/telemetry SDK rules outrank the brand switch.
		{"ms.applovin.com", "", "ads"},
		{"logs.ads.vungle.com", "", "ads"},
		{"app-measurement.com", "", "ads"},
		// ...but a rule with no pinned category leaves the switch in charge:
		// APNs is still apple, the push role carries the nuance.
		{"courier.push.apple.com", "", "apple"},
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

func TestCategorizePortHeuristics(t *testing.T) {
	cases := []struct {
		name   string
		target string
		ip     string
		proto  string
		port   uint16
		want   string
	}{
		// STUN/TURN -> calls, both protocols, both ports.
		{"stun udp", "", "203.0.113.10", "udp", 3478, "calls"},
		{"turn tcp", "", "203.0.113.10", "tcp", 5349, "calls"},
		// Calls to a big org's bare IP are still calls, not "meta browsing".
		{"whatsapp stun", "", "157.240.20.35", "udp", 3478, "calls"},
		// A named STUN host with no domain rule falls through to the port rule.
		{"named stun", "stun.l.google.com", "", "udp", 3478, "calls"},
		// APNs.
		{"apns", "", "17.188.4.20", "tcp", 5223, "apple"},
		{"udp 5223 is not apns", "", "203.0.113.10", "udp", 5223, "other"},
		// Encrypted DNS: port 853 beats the owner-range guess (77.88.8.8 is a
		// Yandex resolver — DoT to it is dns, not "yandex").
		{"dot", "", "9.9.9.9", "tcp", 853, "dns"},
		{"doq", "", "94.140.14.14", "udp", 853, "dns"},
		{"dot to yandex resolver", "", "77.88.8.8", "tcp", 853, "dns"},
		// Nested tunnels/proxies observed in production.
		{"socks-ish 1180", "", "203.0.113.10", "tcp", 1180, "proxy"},
		{"tunnel 12324", "", "203.0.113.10", "tcp", 12324, "proxy"},
		{"warp masque", "", "203.0.113.10", "udp", 2408, "proxy"},
		{"l2tp", "", "203.0.113.10", "udp", 1701, "proxy"},
		{"ipsec nat-t", "", "203.0.113.10", "udp", 4500, "proxy"},
		{"wg-in-wg", "", "203.0.113.10", "udp", 51820, "proxy"},
		{"openvpn tcp", "", "203.0.113.10", "tcp", 1194, "proxy"},
		{"openvpn udp", "", "203.0.113.10", "udp", 1194, "proxy"},
		// WARP pattern: high UDP ports into Cloudflare space only.
		{"warp high port", "", "104.29.153.158", "udp", 19310, "proxy"},
		{"high port elsewhere", "", "8.8.4.4", "udp", 19310, "other"},
		{"warp port range edge", "", "104.29.0.1", "udp", 19330, "proxy"},
		{"cloudflare quic stays cloudflare", "", "104.29.153.158", "udp", 443, "cloudflare"},
		// iCloud Private Relay is a proxy; ordinary iCloud stays apple.
		{"relay mask", "mask.icloud.com", "", "tcp", 443, "proxy"},
		{"relay h2", "mask-h2.icloud.com", "", "tcp", 443, "proxy"},
		{"relay api", "mask-api.icloud.com", "", "udp", 443, "proxy"},
		{"plain icloud", "gateway.icloud.com", "", "tcp", 443, "apple"},
		// Domain evidence still wins over port heuristics.
		{"named dot resolver", "one.one.one.one", "1.1.1.1", "tcp", 853, "dns"},
		{"p2p unchanged", "", "203.0.113.10", "tcp", 6890, "p2p"},
	}
	for _, tc := range cases {
		if got := categorize(tc.target, tc.ip, tc.proto, tc.port); got != tc.want {
			t.Errorf("%s: categorize(%q, %q, %s, %d) = %q, want %q", tc.name, tc.target, tc.ip, tc.proto, tc.port, got, tc.want)
		}
	}
	if org := orgForTargetName("mask-api.icloud.com"); org != "iCloud Private Relay" {
		t.Errorf("orgForTargetName(mask-api) = %q, want iCloud Private Relay", org)
	}
	if org := orgForTargetName("mask.icloud.com"); org != "iCloud Private Relay" {
		t.Errorf("orgForTargetName(mask) = %q, want iCloud Private Relay", org)
	}
}
