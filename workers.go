package main

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"
)

type workerSet map[url.URL]time.Time

// workers represents a set of worker enclaves.  The leader enclave keeps track
// of workers.
type workers struct {
	timeout               time.Duration
	reg, unreg, heartbeat chan *url.URL
	len                   chan int
	f                     chan func(*url.URL)
}

func newWorkers(timeout time.Duration) *workers {
	return &workers{
		timeout:   timeout,
		reg:       make(chan *url.URL),
		unreg:     make(chan *url.URL),
		heartbeat: make(chan *url.URL),
		len:       make(chan int),
		f:         make(chan func(*url.URL)),
	}
}

func (w *workers) monitor(ctx context.Context) {
	var (
		set   = make(map[url.URL]time.Time)
		timer = time.NewTicker(time.Minute)
	)
	elog.Println("Starting worker event loop.")
	defer elog.Println("Stopping worker event loop.")

	for {
		select {
		case <-ctx.Done():
			return

		case <-timer.C:
			go w.pruneDefunctWorkers(set)

		case worker := <-w.reg:
			set[*worker] = time.Now()
			elog.Printf("Registered worker %s; %d worker(s) now registered.",
				worker.Host, len(set))

		case worker := <-w.unreg:
			delete(set, *worker)
			elog.Printf("Unregistered worker %s; %d worker(s) left.",
				worker.Host, len(set))

		case worker := <-w.heartbeat:
			_, exists := set[*worker]
			if !exists {
				elog.Printf("Updating heartbeat for previously-unregistered worker %s.",
					worker.Host)
			}
			set[*worker] = time.Now()

		case f := <-w.f:
			w.runForAll(f, set)
			w.f <- nil // Signal to caller that we're done.

		case <-w.len:
			w.len <- len(set)
		}
	}
}

// runForAll blocks until the given function was run over all workers in our
// set.  For key synchronization, this should never take more than a couple
// seconds.
func (w *workers) runForAll(f func(*url.URL), set workerSet) {
	var wg sync.WaitGroup
	fmt.Printf("# of workers: %d", len(set))
	for worker := range set {
		wg.Add(1)
		go func(wg *sync.WaitGroup, worker *url.URL) {
			f(worker)
			wg.Done()
		}(&wg, &worker)
	}
	wg.Wait()
}

func (w *workers) length() int {
	w.len <- 0 // Signal to the event loop that we want the length.
	return <-w.len
}

func (w *workers) forAll(f func(*url.URL)) {
	w.f <- f
	<-w.f // Wait until the event loop is done running the given function.
}

func (w *workers) register(worker *url.URL) {
	w.reg <- worker
}

func (w *workers) unregister(worker *url.URL) {
	w.unreg <- worker
}

func (w *workers) updateHeartbeat(worker *url.URL) {
	w.heartbeat <- worker
}

func (w *workers) pruneDefunctWorkers(set workerSet) {
	now := time.Now()
	for worker, lastSeen := range set {
		if now.Sub(lastSeen) > w.timeout {
			w.unregister(&worker)
			elog.Printf("Pruned %s from worker set.", worker.Host)
		}
	}
}
