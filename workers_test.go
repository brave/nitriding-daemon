package main

import (
	"net/url"
	"sync"
	"testing"
	"time"
)

func TestWorkerRegistration(t *testing.T) {
	var (
		w    = newWorkerManager(time.Minute)
		stop = make(chan struct{})
	)
	go w.start(stop)
	defer close(stop)

	// Identical URLs are only tracked once.
	worker1 := url.URL{Host: "foo"}
	w.register(&worker1)
	w.register(&worker1)
	assertEqual(t, w.length(), 1)

	worker2 := url.URL{Host: "bar"}
	w.register(&worker2)
	assertEqual(t, w.length(), 2)

	w.unregister(&worker1)
	w.unregister(&worker2)
	// It should be safe to unregister a non-existing worker.
	w.unregister(&worker2)
	assertEqual(t, w.length(), 0)

	// Nothing should happen when attempting to unregister a non-existing
	// worker.
	w.unregister(&url.URL{Host: "does-not-exist"})
}

func TestForAll(t *testing.T) {
	var (
		w     = newWorkerManager(time.Millisecond)
		stop  = make(chan struct{})
		wg    = sync.WaitGroup{}
		mutex = sync.Mutex{}
		total = 0
	)
	go w.start(stop)
	defer close(stop)

	w.register(&url.URL{Host: "foo"})
	w.register(&url.URL{Host: "bar"})
	assertEqual(t, w.length(), 2)

	wg.Add(2)
	w.forAll(
		func(w *url.URL) {
			mutex.Lock()
			defer mutex.Unlock()
			defer wg.Done()
			total += 1
		},
	)
	wg.Wait()
	assertEqual(t, total, 2)
}

func TestIneffectiveForAll(t *testing.T) {
	var (
		w    = newWorkerManager(time.Minute)
		stop = make(chan struct{})
	)
	go w.start(stop)
	defer close(stop)

	// Make sure that forAll finishes for an empty worker set.
	w.forAll(func(_ *url.URL) {})
}
