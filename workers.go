package main

import (
	"fmt"
	"net/url"
)

// worker represents a worker enclave.  The leader enclave is responsible for
// managing key material (for nitriding itself and the enclave application) and
// pushes this key material to worker enclaves.
type worker struct {
	URL *url.URL
}

func (w *worker) String() string {
	return w.URL.String()
}

// workers represents a set of worker enclaves.
type workers []*worker

func (ws workers) push(keyMaterial interface{}) error {
	// TODO: Contact worker enclave and sync key material.
	return nil
}

func (ws workers) pushTo(w *worker, keyMaterial any) error {
	// TODO: Contact worker enclave and sync key material.
	return nil
}

func (ws *workers) register(w *worker) {
	*ws = append(*ws, w)
}

func (ws *workers) registerAndPush(w *worker, keyMaterial any) {
	ws.register(w)
	elog.Printf("Registered new worker enclave %s.", w)
	ws.pushTo(w, keyMaterial)
	elog.Printf("Pushed key material to new worker enclave %s.", w)
}

func (ws *workers) unregister(w *worker) {
	// TODO: Unregister worker enclave.
}

func (ws workers) String() string {
	var s string
	for i, w := range ws {
		s += fmt.Sprintf("%2d: %s\n", i, w)
	}
	return s
}
