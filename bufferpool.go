package main

import (
	"sync"
)

// bufSize represents the buffer size for our reverse proxy.  It's identical to
// the buffer size used in Go's reverse proxy implementation:
// https://cs.opensource.google/go/go/+/refs/tags/go1.20.3:src/net/http/httputil/reverseproxy.go;l=634
const bufSize = 32 * 1024

// bufPool implements the httputil.BufferPool interface.  The implementation is
// based on sync.Pool.
type bufPool struct {
	sync.Pool
}

func newBufPool() *bufPool {
	return &bufPool{
		Pool: sync.Pool{
			New: func() any {
				// The Pool's New function should generally only return pointer
				// types, since a pointer can be put into the return interface
				// value without an allocation:
				s := make([]byte, bufSize)
				return &s
			},
		},
	}
}

func (p *bufPool) Get() []byte {
	s := p.Pool.Get()
	return *s.(*[]byte)
}

func (p *bufPool) Put(buf []byte) {
	p.Pool.Put(&buf)
}
