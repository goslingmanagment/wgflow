package main

import "testing"

func TestTargetServiceDefaultsToRegistrableDomain(t *testing.T) {
	defer setServiceRuleOverrides(nil)
	cases := []struct{ host, want string }{
		{"upload.picsart.com", "picsart.com"},
		{"UPLOAD.PicsArt.com.", "picsart.com"},
		{"amp-api-search-edge.apps.apple.com", "App Store"}, // rule label beats eTLD+1
		{"ms.applovin.com", "AppLovin"},
		{"video-fra5-1.xx.fbcdn.net", "Instagram/Facebook"},
		{"shop.example.co.uk", "example.co.uk"}, // multi-label public suffix
		{"cdn.some-site.spb.ru", "some-site.spb.ru"},
		{"localhost", "localhost"}, // single label: fall back to the host itself
		{"104.29.153.158", ""},     // bare IP: no name, never invent one
		{"", ""},
	}
	for _, tc := range cases {
		if got := targetService(tc.host); got != tc.want {
			t.Errorf("targetService(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

func TestTargetRoleIsSuffixMatchedLongestWins(t *testing.T) {
	defer setServiceRuleOverrides(nil)
	cases := []struct{ host, want string }{
		{"ms4.applovin.com", roleAds},
		{"logs.ads.vungle.com", roleAds},
		{"app-measurement.com", roleTelemetry},
		{"firebaselogging-pa.googleapis.com", roleTelemetry},
		{"www.googleapis.com", ""}, // the apex has no role: only the SDK subdomains do
		{"graph.facebook.com", ""}, // ambiguous (app + SDK): deliberately unlabeled
		{"courier.push.apple.com", rolePush},
		{"gateway.icloud.com", ""},
		{"p61-content.icloud-content.com", roleSync},
		{"mask.icloud.com", roleProxy},
		{"mask-h2.icloud.com", roleProxy},
		{"rr4---sn-4g5edne6.googlevideo.com", roleMedia},
		{"scontent-fra5-1.cdninstagram.com", roleCDN},
		{"dns.google", roleDNS},
		{"upload.picsart.com", ""},
		{"1.1.1.1", ""},
	}
	for _, tc := range cases {
		if got := targetRole(tc.host); got != tc.want {
			t.Errorf("targetRole(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

func TestServiceRuleOverridesMergeAndDelete(t *testing.T) {
	defer setServiceRuleOverrides(nil)
	setServiceRuleOverrides(map[string]serviceRule{
		".picsart.com": {Service: "Picsart"},
		"applovin.com": {}, // all-empty removes the builtin
		"Ads.Example.": {Role: " ADS ", Category: "ads"},
		"":             {Service: "ignored"},
	})
	if got := targetService("upload.picsart.com"); got != "Picsart" {
		t.Errorf("override label: got %q", got)
	}
	if got := targetRole("ms.applovin.com"); got != "" {
		t.Errorf("deleted builtin still matches: %q", got)
	}
	if got := targetRole("x.ads.example"); got != roleAds {
		t.Errorf("normalized override role: got %q", got)
	}
	if got := targetRuleCategory("x.ads.example"); got != "ads" {
		t.Errorf("override category: got %q", got)
	}
	setServiceRuleOverrides(nil)
	if got := targetRole("ms.applovin.com"); got != roleAds {
		t.Errorf("nil should restore builtins, got %q", got)
	}
}

func TestRoleHelpers(t *testing.T) {
	if !isSDKRole(roleAds) || !isSDKRole(roleTelemetry) || isSDKRole(rolePush) || isSDKRole("") {
		t.Fatal("isSDKRole: ads and telemetry only")
	}
	for _, r := range []string{roleAds, roleTelemetry, rolePush, roleCDN, roleSync, roleProxy, roleDNS} {
		if isLeaderRole(r) {
			t.Errorf("%s must never lead a session", r)
		}
	}
	if !isLeaderRole("") || !isLeaderRole(roleMedia) {
		t.Error("unlabeled and media services may lead a session")
	}
}

func TestDirectionHint(t *testing.T) {
	const mib = 1 << 20
	cases := []struct {
		up, down uint64
		want     string
	}{
		{18 * mib, 500 << 10, "upload"},
		{26 << 10, 1660 << 10, "download"},
		{400 << 10, 300 << 10, ""}, // balanced chatter
		{100 << 10, 10 << 10, ""},  // under the byte floor
		{3 * mib, 1 * mib, "upload"},
		{3*mib - 1, 1 * mib, ""},
	}
	for _, tc := range cases {
		if got := directionHint(tc.up, tc.down); got != tc.want {
			t.Errorf("directionHint(%d, %d) = %q, want %q", tc.up, tc.down, got, tc.want)
		}
	}
}
