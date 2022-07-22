package nitriding

import (
	"sync"
	"time"
)

const (
	defaultItemExpiry = time.Minute
)

// cache implements a simple cache whose items expire.
type cache struct {
	sync.RWMutex
	Items map[string]time.Time
	TTL   time.Duration
}

// newCache creates and returns a new cache with the given lifetime for cache
// items.
func newCache(ttl time.Duration) *cache {
	return &cache{
		Items: make(map[string]time.Time),
		TTL:   ttl,
	}
}

// Count returns the number of elements in the cache.
func (c *cache) Count() int {
	c.RLock()
	defer c.RUnlock()

	return len(c.Items)
}

// pruneLater prunes the given element after ttl.
func (c *cache) pruneLater(key string, ttl time.Duration) {
	time.Sleep(ttl)

	c.Lock()
	defer c.Unlock()
	delete(c.Items, key)
}

// Add adds a new string item to the cache.
func (c *cache) Add(key string) {
	c.Lock()
	defer c.Unlock()

	c.Items[key] = time.Now().UTC()
	// Spawn a goroutine that deletes the given element after TTL.  Note that
	// the enclave's endpoint for requesting nonces should not be exposed to
	// the Internet because it would allow adversaries to request nonces at a
	// high rate, thus spawning many goroutines, which would constitute a
	// resource DoS attack.
	go c.pruneLater(key, c.TTL)
}

// Exists returns true if the given string item exists in the cache.  If the
// item exists but is expired, the function returns false.
func (c *cache) Exists(key string) bool {
	c.RLock()
	defer c.RUnlock()
	_, exists := c.Items[key]

	return exists
}
