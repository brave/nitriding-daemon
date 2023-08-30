package main

import (
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
	leader, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("Error creating test server URL: %v", err)
	}
	worker := &url.URL{
		Host: "localhost",
	}

	err = asWorker(e.setupWorkerPostSync, &dummyAttester{}).registerWith(leader, worker)
	if err != nil {
		t.Fatalf("Error registering with leader: %v", err)
	}
	if !hasRegistered {
		t.Fatal("Worker did not register with leader.")
	}
}

func TestSuccessfulSync(t *testing.T) {
	// For key synchronization to be successful, we need actual certificates in
	// the leader keys.
	initLeaderKeysCert(t)

	// Set up the worker.
	worker := createEnclave(&defaultCfg)
	srv := httptest.NewTLSServer(
		asWorker(worker.setupWorkerPostSync, &dummyAttester{}),
	)
	workerURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("Error creating test server URL: %v", err)
	}

	if err = asLeader(leaderKeys, &dummyAttester{}).syncWith(workerURL); err != nil {
		t.Fatalf("Error syncing with leader: %v", err)
	}

	// Make sure that the keys were synced correctly.
	if !worker.keys.equal(leaderKeys) {
		t.Fatalf("Keys differ between worker and leader:\n%v (worker)\n%v (leader)",
			leaderKeys, worker.keys)
	}
}
