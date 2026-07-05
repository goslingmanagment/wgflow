package main

import (
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
