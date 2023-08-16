package main

import (
	"context"
	"net/url"
	"testing"
	"time"
)

func TestWorkerRegistration(t *testing.T) {
	var (
		w           = newWorkerManager(time.Minute)
		ctx, cancel = context.WithCancel(context.Background())
	)
	go w.start(ctx)
	defer cancel()

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
		w           = newWorkerManager(time.Minute)
		ctx, cancel = context.WithCancel(context.Background())
	)
	go w.start(ctx)
	defer cancel()

	w.register(&url.URL{Host: "foo"})
	w.register(&url.URL{Host: "bar"})
	assertEqual(t, w.length(), 2)

	total := 0
	w.forAll(
		func(w *url.URL) {
			total += 1
		},
	)
	// Make sure that the worker got pruned after the next tick.
	w._afterTick(func() {
		assertEqual(t, total, 2)
	})
}

func TestIneffectiveForAll(t *testing.T) {
	var (
		w           = newWorkerManager(time.Minute)
		ctx, cancel = context.WithCancel(context.Background())
	)
	go w.start(ctx)
	defer cancel()

	// Make sure that forAll finishes for an empty worker set.
	w.forAll(func(_ *url.URL) {})
}

func TestUpdatingAndPruning(t *testing.T) {
	var (
		w           = newWorkerManager(time.Millisecond)
		ctx, cancel = context.WithCancel(context.Background())
	)
	go w.start(ctx)
	defer cancel()

	worker := &url.URL{Host: "foo"}
	w.register(worker)
	assertEqual(t, w.length(), 1)

	// Make sure that the worker got pruned after the next tick.
	w._afterTick(func() {
		assertEqual(t, w.length(), 0)
	})
}
