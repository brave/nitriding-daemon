package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// leaderKeys holds arbitrary keys that we use for testing.
var leaderKeys = &enclaveKeys{
	NitridingKey:  []byte("NitridingTestKey"),
	NitridingCert: []byte("NitridingTestCert"),
	AppKeys:       []byte("AppTestKeys"),
}

func initLeaderKeysCert(t *testing.T) {
	t.Helper()
	cert, key, err := createCertificate("example.com")
	if err != nil {
		t.Fatal(err)
	}
	leaderKeys.setNitridingKeys(key, cert)
}

func TestSuccessfulRegisterWith(t *testing.T) {
	e := createEnclave(&defaultCfg)
	hasRegistered := false

	srv := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			hasRegistered = true
			w.WriteHeader(http.StatusOK)
		}),
	)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("Error creating test server URL: %v", err)
	}

	err = asWorker(e.installKeys, make(chan struct{})).registerWith(u)
	if err != nil {
		t.Fatalf("Error registering with leader: %v", err)
	}
	if !hasRegistered {
		t.Fatal("Worker did not register with leader.")
	}
}

func TestAbortedRegisterWith(t *testing.T) {
	e := createEnclave(&defaultCfg)

	// Provide a bogus URL that cannot be synced with.
	bogusURL := &url.URL{
		Scheme: "https",
		Host:   "localhost:1",
	}
	abortChan := make(chan struct{})
	ret := make(chan error)
	go func(ret chan error) {
		ret <- asWorker(e.installKeys, abortChan).registerWith(bogusURL)
	}(ret)

	// Designate the enclave as leader, after which registration should abort.
	close(abortChan)
	if err := <-ret; !errors.Is(err, errBecameLeader) {
		t.Fatal("Enclave did not realize that it became leader.")
	}
}

func TestSuccessfulSync(t *testing.T) {
	// For key synchronization to be successful, we need actual certificates in
	// the leader keys.
	initLeaderKeysCert(t)

	// Set up the worker.
	worker := createEnclave(&defaultCfg)
	srv := httptest.NewTLSServer(
		asWorker(worker.installKeys, make(chan struct{})),
	)
	workerURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("Error creating test server URL: %v", err)
	}

	if err = asLeader(leaderKeys).syncWith(workerURL); err != nil {
		t.Fatalf("Error syncing with leader: %v", err)
	}

	// Make sure that the keys were synced correctly.
	if !worker.keys.equal(leaderKeys) {
		t.Fatalf("Keys differ between worker and leader:\n%v (worker)\n%v (leader)",
			leaderKeys, worker.keys)
	}
}
