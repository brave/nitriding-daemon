package main

import (
	"net/url"
	"sync"
	"time"
)

// workers represents a set of worker enclaves.  The leader enclave keeps track
// of workers.
type workers struct {
	sync.RWMutex
	timeout time.Duration
	set     map[url.URL]time.Time
}

func newWorkers(timeout time.Duration) *workers {
	return &workers{
		set:     make(map[url.URL]time.Time),
		timeout: timeout,
	}
}

func (w *workers) length() int {
	w.RLock()
	defer w.RUnlock()

	return len(w.set)
}

func (w *workers) register(worker *url.URL) {
	w.Lock()
	defer w.Unlock()

	w.set[*worker] = time.Now()
	elog.Printf("Registered worker %s; %d worker(s) now registered.",
		worker.String(), len(w.set))
}

func (w *workers) unregister(worker *url.URL) {
	w.Lock()
	defer w.Unlock()

	delete(w.set, *worker)
	elog.Printf("Unregistered worker %s; %d worker(s) left.",
		worker.String(), len(w.set))
}

func (w *workers) updateAndPrune(worker *url.URL) {
	w.updateHeartbeat(worker)
	w.pruneDefunctWorkers()
}

func (w *workers) updateHeartbeat(worker *url.URL) {
	w.Lock()
	defer w.Unlock()

	_, exists := w.set[*worker]
	if !exists {
		elog.Printf("Updating heartbeat for previously-unregistered worker %s.", worker)
	}
	w.set[*worker] = time.Now()
}

func (w *workers) pruneDefunctWorkers() {
	w.RLock()
	defer w.RUnlock()

	now := time.Now()
	for worker, lastSeen := range w.set {
		if now.Sub(lastSeen) > w.timeout {
			w.unregister(&worker)
		}
	}
}
