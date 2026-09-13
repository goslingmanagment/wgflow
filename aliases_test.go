package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAliasConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.yaml")
	cfg := `
people:
  - display: Diana
    devices: [diana-iphone, diana-macbook]
  - display: Мама
    devices: [mom-macbook]
device_kind:
  mom-macbook: laptop
`
	if err := os.WriteFile(path, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}
	ac, err := loadAliasConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if ac.Person("diana-iphone") != "Diana" || ac.Person("diana-macbook") != "Diana" {
		t.Errorf("diana devices should map to Diana")
	}
	if ac.Person("mom-macbook") != "Мама" {
		t.Errorf("mom-macbook = %q, want Мама", ac.Person("mom-macbook"))
	}
	if ac.Person("guest-iphone") != "guest" { // unmapped -> prefix fallback
		t.Errorf("unmapped fallback = %q, want guest", ac.Person("guest-iphone"))
	}
	if ac.Person("mom") != "mom" { // hyphenless -> whole name, never orphaned
		t.Errorf("hyphenless fallback = %q, want mom", ac.Person("mom"))
	}
	if ac.Kind("mom-macbook") != "laptop" {
		t.Errorf("kind override = %q, want laptop", ac.Kind("mom-macbook"))
	}
	if ac.Kind("diana-iphone") != "" {
		t.Errorf("no override should be empty")
	}
	if len(ac.Roster()) != 3 {
		t.Errorf("roster = %v, want 3 devices", ac.Roster())
	}
}

func TestAliasConfigFallbacks(t *testing.T) {
	// missing file -> empty (not error), nil receiver -> same fallbacks
	ac, err := loadAliasConfig(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var nilAC *AliasConfig
	for _, a := range []*AliasConfig{ac, nilAC} {
		if a.Person("diana-iphone") != "diana" {
			t.Errorf("fallback Person = %q, want diana", a.Person("diana-iphone"))
		}
		if a.Kind("x") != "" || a.Roster() != nil {
			t.Errorf("empty/nil config should have no kind/roster")
		}
	}
}

func TestLoadAliasConfigInstallsServiceRules(t *testing.T) {
	defer setServiceRuleOverrides(nil)
	defer setTargetNameOverrides(nil)
	path := filepath.Join(t.TempDir(), "clients.yaml")
	cfg := `
people:
  - display: Diana
    devices: [diana-iphone]
services:
  "picsart.com":
    service: Picsart
  "ads.example.net":
    role: ads
    category: ads
  "applovin.com": {}
`
	if err := os.WriteFile(path, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAliasConfig(path); err != nil {
		t.Fatal(err)
	}
	if got := targetService("upload.picsart.com"); got != "Picsart" {
		t.Errorf("configured label = %q, want Picsart", got)
	}
	if got := targetRole("track.ads.example.net"); got != roleAds {
		t.Errorf("configured role = %q, want ads", got)
	}
	if got := targetRuleCategory("track.ads.example.net"); got != "ads" {
		t.Errorf("configured category = %q, want ads", got)
	}
	if got := targetRole("ms.applovin.com"); got != "" {
		t.Errorf("empty mapping must delete the builtin, got role %q", got)
	}
	// Builtins the file does not mention survive the merge.
	if got := targetService("p61-content.icloud-content.com"); got != "iCloud" {
		t.Errorf("untouched builtin = %q, want iCloud", got)
	}

	// A missing config restores pure defaults.
	if _, err := loadAliasConfig(filepath.Join(t.TempDir(), "nope.yaml")); err != nil {
		t.Fatal(err)
	}
	if got := targetRole("ms.applovin.com"); got != roleAds {
		t.Errorf("missing config must restore builtins, got %q", got)
	}
}
