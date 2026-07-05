package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
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

func TestDomainCacheSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.cache.json")
	d := NewDomainCache()
	d.Put("10.66.66.6", "142.250.1.1", "youtube.com", 600)
	d.Put("10.66.66.7", "104.16.0.1", "cloudflare.com", 600)
	// An already-expired entry must not survive the round trip.
	d.Put("10.66.66.8", "198.51.100.9", "dead.example.com", 600)
	past := time.Now().Add(-time.Second)
	d.mu.Lock()
	ent := d.byClientIP["10.66.66.8|198.51.100.9"]
	ent.Expires = past
	d.byClientIP["10.66.66.8|198.51.100.9"] = ent
	ent = d.byIP["198.51.100.9"]
	ent.Expires = past
	d.byIP["198.51.100.9"] = ent
	d.mu.Unlock()

	if err := d.SaveTo(path); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}
	restored := NewDomainCache()
	n, err := restored.LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if n == 0 {
		t.Fatal("LoadFrom restored nothing")
	}
	if got := restored.Lookup("10.66.66.6", "142.250.1.1"); got != "youtube.com" {
		t.Fatalf("client-scoped lookup after restore = %q, want youtube.com", got)
	}
	if got := restored.Lookup("10.66.66.99", "104.16.0.1"); got != "cloudflare.com" {
		t.Fatalf("byIP lookup after restore = %q, want cloudflare.com", got)
	}
	if got := restored.Lookup("10.66.66.8", "198.51.100.9"); got != "" {
		t.Fatalf("expired entry survived restore: %q", got)
	}
}

func TestDomainCacheLoadCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.cache.json")
	if err := os.WriteFile(path, []byte("{not json"), 0644); err != nil {
		t.Fatal(err)
	}
	d := NewDomainCache()
	if _, err := d.LoadFrom(path); err == nil {
		t.Fatal("LoadFrom must fail on a corrupt file")
	}
	// The cache stays usable after a failed load.
	d.Put("10.66.66.6", "142.250.1.1", "youtube.com", 600)
	if got := d.Lookup("10.66.66.6", "142.250.1.1"); got != "youtube.com" {
		t.Fatalf("cache unusable after failed load, Lookup = %q", got)
	}
}

func TestDomainCacheLoadVersionMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.cache.json")
	body := fmt.Sprintf(`{"version":%d,"by_client_ip":{},"by_ip":{}}`, domainCacheFileVersion+1)
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDomainCache().LoadFrom(path); err == nil {
		t.Fatal("LoadFrom must reject an unknown format version")
	}
}

func TestDomainCacheLoadMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.cache.json")
	_, err := NewDomainCache().LoadFrom(path)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file must surface os.ErrNotExist, got %v", err)
	}
}

func TestDomainCacheLoadRespectsCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.cache.json")
	d := NewDomainCache()
	for i := 0; i < 10; i++ {
		d.Put("10.66.66.6", fmt.Sprintf("192.0.2.%d", i), fmt.Sprintf("h%d.example.com", i), 600)
	}
	if err := d.SaveTo(path); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}
	restored := NewDomainCache()
	restored.maxEntries = 3
	if _, err := restored.LoadFrom(path); err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	restored.mu.RLock()
	defer restored.mu.RUnlock()
	if len(restored.byClientIP) > 3 || len(restored.byIP) > 3 {
		t.Fatalf("load ignored cap: %d/%d entries", len(restored.byClientIP), len(restored.byIP))
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

func TestClientMapMatchDirection(t *testing.T) {
	_, vpn, err := net.ParseCIDR("10.66.66.0/24")
	if err != nil {
		t.Fatal(err)
	}
	clients := &ClientMap{
		byIP:    map[string]string{"10.66.66.6": "alice"},
		vpnNets: []*net.IPNet{vpn},
	}

	clientIP, name, outbound, ok := clients.Match(net.ParseIP("10.66.66.6"), net.ParseIP("8.8.8.8"))
	if !ok || !outbound || clientIP != "10.66.66.6" || name != "alice" {
		t.Fatalf("outbound match = (%q, %q, %v, %v)", clientIP, name, outbound, ok)
	}

	clientIP, name, outbound, ok = clients.Match(net.ParseIP("8.8.8.8"), net.ParseIP("10.66.66.6"))
	if !ok || outbound || clientIP != "10.66.66.6" || name != "alice" {
		t.Fatalf("inbound match = (%q, %q, %v, %v)", clientIP, name, outbound, ok)
	}
}
