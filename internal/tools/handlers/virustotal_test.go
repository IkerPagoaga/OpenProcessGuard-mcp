package handlers

import (
	"testing"
	"time"
)

// TestEvictExpiredLocked locks the cache-eviction sweep that bounds vtCache: entries
// at or past the TTL are dropped, fresh entries survive. This is the leak fix wired
// into LookupHash's leader path, which previously never freed an expired entry.
//
// Must stay non-parallel: it replaces the package-global vtCache under vtCacheMu and
// resets it before unlocking, so a t.Parallel() here (or on any LookupHash test) would
// collide on the shared cache.
func TestEvictExpiredLocked(t *testing.T) {
	now := time.Now()

	vtCacheMu.Lock()
	vtCache = map[string]vtCacheEntry{
		"fresh": {report: VTReport{Hash: "fresh"}, cachedAt: now.Add(-time.Minute)},
		"stale": {report: VTReport{Hash: "stale"}, cachedAt: now.Add(-2 * vtCacheTTL)},
		"edge":  {report: VTReport{Hash: "edge"}, cachedAt: now.Add(-vtCacheTTL)}, // exactly TTL → expired (>=)
	}
	removed := evictExpiredLocked(now)
	_, freshOK := vtCache["fresh"]
	_, staleOK := vtCache["stale"]
	_, edgeOK := vtCache["edge"]
	remaining := len(vtCache)
	// Reset shared package state so we don't leak fixtures into other tests.
	vtCache = map[string]vtCacheEntry{}
	vtCacheMu.Unlock()

	if removed != 2 {
		t.Errorf("evictExpiredLocked removed %d, want 2", removed)
	}
	if !freshOK {
		t.Errorf("fresh entry was evicted; should survive")
	}
	if staleOK {
		t.Errorf("stale entry (2×TTL) survived; should be evicted")
	}
	if edgeOK {
		t.Errorf("edge entry (exactly TTL) survived; >= TTL must be evicted")
	}
	if remaining != 1 {
		t.Errorf("remaining cache size = %d, want 1", remaining)
	}
}
