package dns

import (
	"sync"
	"time"
)

// cache is a small TTL cache for DNS answers. The cache exists to keep the
// toolkit from asking the same question of an authoritative server once per
// module, which matters for both politeness and for the request budget.
//
// It is bounded in size so that a crawl over a large domain cannot grow it
// without limit.
type cache struct {
	mu   sync.RWMutex
	ttl  time.Duration
	max  int
	seen map[string]cacheEntry
}

type cacheEntry struct {
	records []dnsRecord
	expires time.Time
}

type dnsRecord struct {
	name     string
	typeName string
	value    string
}

func newCache(ttl time.Duration) *cache {
	return &cache{ttl: ttl, max: 4096, seen: map[string]cacheEntry{}}
}

// get returns a cached answer. A cache with a non-positive TTL is disabled
// outright rather than relying on expiry arithmetic: the system clock has a
// coarse resolution on some platforms, so a zero TTL would still serve hits
// for several milliseconds.
func (c *cache) get(key string) ([]dnsRecord, bool) {
	if c == nil || c.ttl <= 0 {
		return nil, false
	}
	c.mu.RLock()
	e, ok := c.seen[key]
	c.mu.RUnlock()
	if !ok || !time.Now().Before(e.expires) {
		return nil, false
	}
	return e.records, true
}

// put stores an answer. A disabled cache stores nothing at all, so it also
// cannot grow.
func (c *cache) put(key string, recs []dnsRecord) {
	if c == nil || c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.seen) >= c.max {
		// Drop everything rather than track ages: a full cache means the run
		// is large, and a periodic flush costs a little accuracy for a hard
		// memory bound.
		c.seen = map[string]cacheEntry{}
	}
	c.seen[key] = cacheEntry{records: recs, expires: time.Now().Add(c.ttl)}
}

// Purge empties the cache.
func (c *cache) Purge() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.seen = map[string]cacheEntry{}
	c.mu.Unlock()
}

// Len reports the number of cached entries.
func (c *cache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.seen)
}
