package nitriding

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"

	"github.com/mdlayher/vsock"
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

func listenHTTP01(errChan chan error, mgr *autocert.Manager) {
	// Let's Encrypt's HTTP-01 challenge requires a listener on port 80:
	// https://letsencrypt.org/docs/challenge-types/#http-01-challenge
	var l net.Listener
	var err error

	if inEnclave {
		l, err = vsock.Listen(uint32(80), nil)
		if err != nil {
			errChan <- errHTTP01Failed
			return
		}
		defer func() {
			_ = l.Close()
		}()
	} else {
		l, err = net.Listen("tcp", ":80")
		if err != nil {
			errChan <- errHTTP01Failed
			return
		}
	}

	elog.Print("Starting autocert listener.")
	errChan <- nil
	_ = http.Serve(l, mgr.HTTPHandler(nil))
}
