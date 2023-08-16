package main

import (
	"context"
	"net/url"
	"time"
)

// workerManager manages worker enclaves.
type workerManager struct {
	timeout       time.Duration
	reg, unreg    chan *url.URL
	len           chan int
	forAllFunc    chan func(*url.URL)
	afterTickFunc chan func()
}

// workers maps worker enclaves to a timestamp that keeps track of when we last
// got a heartbeat from the enclave.
type workers map[url.URL]time.Time

func newWorkerManager(timeout time.Duration) *workerManager {
	return &workerManager{
		timeout:       timeout,
		reg:           make(chan *url.URL),
		unreg:         make(chan *url.URL),
		len:           make(chan int),
		forAllFunc:    make(chan func(*url.URL)),
		afterTickFunc: make(chan func()),
	}
}

// start starts the worker manager's event loop.
func (w *workerManager) start(ctx context.Context) {
	var (
		set           = make(workers)
		timer         = time.NewTicker(w.timeout)
		afterTickFunc = func() {}
	)
	elog.Println("Starting worker event loop.")
	defer elog.Println("Stopping worker event loop.")

	for {
		select {
		case <-ctx.Done():
			return

		case f := <-w.afterTickFunc:
			afterTickFunc = f

		case <-timer.C:
			go w.pruneDefunctWorkers(set)
			afterTickFunc()

		case worker := <-w.reg:
			set[*worker] = time.Now()
			elog.Printf("Registered worker %s; %d worker(s) now registered.",
				worker.Host, len(set))

		case worker := <-w.unreg:
			delete(set, *worker)
			elog.Printf("Unregistered worker %s; %d worker(s) left.",
				worker.Host, len(set))

		case f := <-w.forAllFunc:
			w.runForAll(f, set)

		case <-w.len:
			w.len <- len(set)
		}
	}
}

// runForAll runs the given function over all workers in our set.  For key
// synchronization, this should never take more than a couple seconds.
func (w *workerManager) runForAll(f func(*url.URL), set workers) {
	for worker := range set {
		go f(&worker)
	}
}

// _afterTick runs the given function after the next event loop tick.  This is
// only useful in unit tests.
func (w *workerManager) _afterTick(f func()) {
	w.afterTickFunc <- f
}

// length returns the number of workers that are currently registered.
func (w *workerManager) length() int {
	w.len <- 0 // Signal to the event loop that we want the length.
	return <-w.len
}

// forAll runs the given function over all registered workers.
func (w *workerManager) forAll(f func(*url.URL)) {
	w.forAllFunc <- f
}

// register registers a new worker enclave.  It is safe to repeatedly register
// the same worker enclave.
func (w *workerManager) register(worker *url.URL) {
	w.reg <- worker
}

// unregister unregisters the given worker enclave.
func (w *workerManager) unregister(worker *url.URL) {
	w.unreg <- worker
}

// pruneDefunctWorkers looks for and unregisters workers whose last heartbeat is
// older than our timeout.
func (w *workerManager) pruneDefunctWorkers(set workers) {
	now := time.Now()
	for worker, lastSeen := range set {
		if now.Sub(lastSeen) > w.timeout {
			w.unregister(&worker)
			elog.Printf("Pruned %s from worker set.", worker.Host)
		}
	}
}
