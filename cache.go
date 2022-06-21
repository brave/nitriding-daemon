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

// newCache creates and returns a new cache with the given expiry date for
// cache items.
func newCache(ttl time.Duration) *cache {
	return &cache{
		Items: make(map[string]time.Time),
		TTL:   ttl,
	}
}

// Add adds a new string item to the cache.
func (c *cache) Add(key string) {
	c.Lock()
	defer c.Unlock()

	c.Items[key] = time.Now().UTC()
}

// Exists returns true if the given string item exists in the cache.  If the
// item exists but is expired, the function returns false.
func (c *cache) Exists(key string) bool {
	// Prune all expired cache items before checking if the given item exists.
	// While that's inefficient, we don't care here because we use our cache
	// only when enclaves synchronize their key material, which is rare.
	c.prune()

	c.RLock()
	defer c.RUnlock()
	_, exists := c.Items[key]

	return exists
}

// prune removes expired items from the cache.
func (c *cache) prune() {
	c.Lock()
	defer c.Unlock()

	now := time.Now().UTC()
	for item, expiryDate := range c.Items {
		itemAge := now.Sub(expiryDate)
		if itemAge > c.TTL {
			delete(c.Items, item)
		}
	}
}
