package main

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"

	"golang.org/x/crypto/acme/autocert"
)

// certRetriever stores an HTTPS certificate and implements the GetCertificate
// function signature, which allows our Web servers to retrieve the
// certificate when clients connect:
// https://pkg.go.dev/crypto/tls#Config
type certRetriever struct {
	sync.RWMutex
	cert *tls.Certificate
}

func (c *certRetriever) set(cert *tls.Certificate) {
	c.Lock()
	defer c.Unlock()

	c.cert = cert
}

func (c *certRetriever) get(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.RLock()
	defer c.RUnlock()

	if c.cert == nil {
		return nil, errors.New("certificate not yet initialized")
	}
	return c.cert, nil
}

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
