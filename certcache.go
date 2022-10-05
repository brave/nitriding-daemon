package nitriding

import (
	"context"
	"errors"
	"sync"

	"golang.org/x/crypto/acme/autocert"
)

var (
	errHTTP01Failed = errors.New("failed to listen for HTTP-01 challenge")
)

// certCache implements the autocert.Cache interface.
type certCache struct {
	sync.RWMutex
	cache map[string][]byte
}

func newCertCache() *certCache {
	return &certCache{
		cache: make(map[string][]byte),
	}
}

func (c *certCache) Get(ctx context.Context, key string) ([]byte, error) {
	c.RLock()
	defer c.RUnlock()

	cert, exists := c.cache[key]
	if !exists {
		return nil, autocert.ErrCacheMiss
	}
	return cert, nil
}

func (c *certCache) Put(ctx context.Context, key string, data []byte) error {
	c.Lock()
	defer c.Unlock()

	c.cache[key] = data
	return nil
}

func (c *certCache) Delete(ctx context.Context, key string) error {
	c.Lock()
	defer c.Unlock()

	delete(c.cache, key)
	return nil
}
