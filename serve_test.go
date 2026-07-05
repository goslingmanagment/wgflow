package main

import (
	"fmt"
	"testing"
	"time"
)

func TestDomainCachePutLookup(t *testing.T) {
	d := NewDomainCache()
	d.Put("10.66.66.6", "142.250.1.1", "youtube.com.", 600)

	if got := d.Lookup("10.66.66.6", "142.250.1.1"); got != "youtube.com" {
		t.Fatalf("Lookup = %q, want youtube.com (trailing dot stripped)", got)
	}
	// Another client hitting the same IP falls back to the shared byIP map.
	if got := d.Lookup("10.66.66.7", "142.250.1.1"); got != "youtube.com" {
		t.Fatalf("byIP fallback = %q, want youtube.com", got)
	}
	if got := d.Lookup("10.66.66.6", "1.2.3.4"); got != "" {
		t.Fatalf("unknown IP = %q, want empty", got)
	}
}

func TestDomainCacheTTLExpiry(t *testing.T) {
	d := NewDomainCache()
	d.Put("10.66.66.6", "142.250.1.1", "youtube.com", 600)
	// Force the entries into the past instead of sleeping through a real TTL.
	past := time.Now().Add(-time.Second)
	d.mu.Lock()
	for k, ent := range d.byClientIP {
		ent.Expires = past
		d.byClientIP[k] = ent
	}
	for k, ent := range d.byIP {
		ent.Expires = past
		d.byIP[k] = ent
	}
	d.mu.Unlock()

	if got := d.Lookup("10.66.66.6", "142.250.1.1"); got != "" {
		t.Fatalf("expired Lookup = %q, want empty", got)
	}
	d.PruneExpired(time.Now())
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.byClientIP) != 0 || len(d.byIP) != 0 {
		t.Fatalf("PruneExpired left %d/%d entries", len(d.byClientIP), len(d.byIP))
	}
}

func TestDomainCacheZeroTTLDefaults(t *testing.T) {
	d := NewDomainCache()
	d.Put("10.66.66.6", "142.250.1.1", "youtube.com", 0)
	if got := d.Lookup("10.66.66.6", "142.250.1.1"); got != "youtube.com" {
		t.Fatalf("ttl=0 must default to a positive TTL, Lookup = %q", got)
	}
}

func TestDomainCacheEvictionCap(t *testing.T) {
	d := &DomainCache{
		byClientIP: map[string]domainEntry{},
		byIP:       map[string]domainEntry{},
		maxEntries: 4,
	}
	for i := 0; i < 20; i++ {
		d.Put("10.66.66.6", fmt.Sprintf("192.0.2.%d", i), fmt.Sprintf("host%d.example", i), 600)
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	// The cap check runs before insert, so the maps may sit at most one entry
	// over the limit but can never grow unbounded.
	if len(d.byClientIP) > 5 || len(d.byIP) > 5 {
		t.Fatalf("cache over cap: byClientIP=%d byIP=%d, max 4(+1 in flight)", len(d.byClientIP), len(d.byIP))
	}
}

func TestDomainCacheEvictsExpiredFirst(t *testing.T) {
	d := &DomainCache{
		byClientIP: map[string]domainEntry{},
		byIP:       map[string]domainEntry{},
		maxEntries: 3,
	}
	// Both maps sit at the cap with one expired entry each: the insert must
	// evict the expired entry, not a live one.
	past := time.Now().Add(-time.Second)
	live := time.Now().Add(time.Hour)
	d.byIP["1.1.1.1"] = domainEntry{Domain: "old.example", Expires: past}
	d.byIP["2.2.2.2"] = domainEntry{Domain: "live.example", Expires: live}
	d.byIP["3.3.3.3"] = domainEntry{Domain: "live2.example", Expires: live}
	d.byClientIP["c|1.1.1.1"] = domainEntry{Domain: "old.example", Expires: past}
	d.byClientIP["c|2.2.2.2"] = domainEntry{Domain: "live.example", Expires: live}
	d.byClientIP["c|3.3.3.3"] = domainEntry{Domain: "live2.example", Expires: live}

	d.Put("c", "4.4.4.4", "new.example", 600)

	if got := d.Lookup("c", "2.2.2.2"); got != "live.example" {
		t.Fatalf("live entry evicted before expired one: Lookup = %q", got)
	}
	if got := d.Lookup("c", "4.4.4.4"); got != "new.example" {
		t.Fatalf("new entry missing after eviction: Lookup = %q", got)
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if _, ok := d.byIP["1.1.1.1"]; ok {
		t.Fatal("expired byIP entry survived eviction")
	}
}
