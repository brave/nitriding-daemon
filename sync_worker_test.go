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
	defer srv.Close()
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

	var mockAppRequests []mockAppRequestInfo
	mockAppServer := createMockServer(nil, &mockAppRequests)
	defer mockAppServer.Close()

	// Set up the worker.
	cfg := defaultCfg
	appURL, err := url.Parse(mockAppServer.URL)
	if err != nil {
		t.Fatalf("Error creating mock app test server URL: %v", err)
	}
	cfg.AppWebSrv = appURL

	worker := createEnclave(&cfg)
	srv := httptest.NewTLSServer(
		asWorker(worker.setupWorkerPostSync, &dummyAttester{}),
	)
	defer srv.Close()
	workerURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("Error creating test server URL: %v", err)
	}

	if err = asLeader(leaderKeys, &dummyAttester{}).syncWith(workerURL); err != nil {
		t.Fatalf("Error syncing with leader: %v", err)
	}

	assertEqual(t, len(mockAppRequests), 1)
	assertEqual(t, mockAppRequests[0].method, http.MethodPut)
	assertEqual(t, mockAppRequests[0].path, "/enclave/state")
	assertEqual(t, string(mockAppRequests[0].body), string(leaderKeys.AppKeys))

	// Make sure that the keys were synced correctly.
	if !worker.keys.equal(leaderKeys) {
		t.Fatalf("Keys differ between worker and leader:\n%v (worker)\n%v (leader)",
			leaderKeys, worker.keys)
	}
}
