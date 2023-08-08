package main

import (
	"net/url"
	"sync"
)

// workers represents a set of worker enclaves.  The leader enclave keeps track
// of workers.
type workers struct {
	sync.RWMutex
	set map[url.URL]struct{}
}

func newWorkers() *workers {
	return &workers{
		set: make(map[url.URL]struct{}),
	}
}

func (w *workers) register(u *url.URL) {
	w.Lock()
	defer w.Unlock()

	w.set[*u] = struct{}{}
}

func (w *workers) unregister(u *url.URL) {
	w.Lock()
	defer w.Unlock()

	delete(w.set, *u)
}
