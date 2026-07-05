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
