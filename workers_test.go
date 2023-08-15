package main

import (
	"net/url"
	"testing"
	"time"
)

func TestWorkerRegistration(t *testing.T) {
	w := newWorkers(time.Minute)

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
	assertEqual(t, w.length(), 0)

	// Nothing should happen when attempting to unregister a non-existing
	// worker.
	w.unregister(&url.URL{Host: "does-not-exist"})
}

func TestUpdatingAndPruning(t *testing.T) {
	// TODO
}
