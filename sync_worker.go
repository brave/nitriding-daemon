package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"
)

var (
	errInProgress      = errors.New("key sync already in progress")
	errFailedToDecrypt = errors.New("error decrypting enclave keys")
	errHashNotInAttstn = errors.New("hash of encrypted keys not in attestation document")

	maxInterimStateAgeSeconds = 10.0
)

type interimSyncState struct {
	ephemeralKey *boxKey
	nonce        nonce
	startTime    time.Time
}

// workerSync holds the state and code that we need for a one-off sync with a
// leader enclave.  workerSync implements the http.Handler interface because the
// sync protocol requires two endpoints on the worker.
type workerSync struct {
	attester
	setupWorker       func(*enclaveKeys) error
	interimStateMutex sync.Mutex
	interimState      *interimSyncState
}

// asWorker returns a new workerSync object.
func asWorker(
	setupWorker func(*enclaveKeys) error,
	a attester,
) *workerSync {
	return &workerSync{
		attester:    a,
		setupWorker: setupWorker,
	}
}

type heartbeatRequest struct {
	HashedKeys     string `json:"hashed_keys"`
	WorkerHostname string `json:"worker_hostname"`
}

// registerWith registers the given worker with the given leader enclave.
func (s *workerSync) registerWith(leader, worker *url.URL) error {
	elog.Println("Attempting to sync with leader.")

	errChan := make(chan error)
	register := func(e chan error) {
		body, err := json.Marshal(heartbeatRequest{WorkerHostname: worker.Host})
		if err != nil {
			e <- err
			return
		}
		resp, err := newUnauthenticatedHTTPClient().Post(leader.String(), "text/plain", bytes.NewBuffer(body))
		if err != nil {
			e <- err
			return
		}
		if resp.StatusCode != http.StatusOK {
			e <- fmt.Errorf("leader returned HTTP code %d", resp.StatusCode)
			return
		}
		e <- nil
	}
	go register(errChan)

	// Keep on trying every five seconds, for a minute.
	retry := time.NewTicker(5 * time.Second)
	timeout := time.NewTicker(time.Minute)
	for {
		select {
		case err := <-errChan:
			if err == nil {
				elog.Println("Successfully registered with leader.")
				return nil
			}
			elog.Printf("Error registering with leader: %v", err)
		case <-timeout.C:
			return errors.New("timed out syncing with leader")
		case <-retry.C:
			go register(errChan)
		}
	}
}

func (s *workerSync) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.initSync(w, r)
	} else if r.Method == http.MethodPost {
		s.finishSync(w, r)
	}
}

// initSync responds to the leader's request for initiating key synchronization.
func (s *workerSync) initSync(w http.ResponseWriter, r *http.Request) {
	elog.Println("Received leader's request to initiate key sync.")

	s.interimStateMutex.Lock()
	defer s.interimStateMutex.Unlock()
	// There must not be more than one key synchronization attempt at any given
	// time.  Abort if we get another request while key synchronization is still
	// in progress.
	if s.interimState != nil &&
		time.Since(s.interimState.startTime).Seconds() < maxInterimStateAgeSeconds {
		http.Error(w, errInProgress.Error(), http.StatusTooManyRequests)
		return
	}

	// Extract the leader's nonce from the URL, which must look like this:
	// https://example.com/enclave/sync?nonce=[HEX-ENCODED-NONCE]
	leadersNonce, err := getNonceFromReq(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Create the worker's nonce and store it in our channel, so we can later
	// verify it.
	workersNonce, err := newNonce()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create an ephemeral key that the leader is going to use to encrypt
	// its enclave keys.
	boxKey, err := newBoxKey()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.interimState = &interimSyncState{
		ephemeralKey: boxKey,
		nonce:        workersNonce,
		startTime:    time.Now(),
	}

	// Create and return the worker's Base64-encoded attestation document.
	attstnDoc, err := s.createAttstn(&workerAuxInfo{
		WorkersNonce: workersNonce,
		LeadersNonce: leadersNonce,
		PublicKey:    boxKey.pubKey[:],
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respBody, err := json.Marshal(&attstnBody{
		Document: base64.StdEncoding.EncodeToString(attstnDoc),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintln(w, string(respBody))
}

// finishSync responds to the leader's final request before key synchronization
// is complete.
func (s *workerSync) finishSync(w http.ResponseWriter, r *http.Request) {
	var (
		reqBody attstnBody
		keys    enclaveKeys
	)
	elog.Println("Received leader's request to complete key sync.")

	// Read the leader's Base64-encoded attestation document.
	maxReadLen := base64.StdEncoding.EncodedLen(maxAttstnBodyLen)
	jsonBody, err := io.ReadAll(newLimitReader(r.Body, maxReadLen))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.Unmarshal(jsonBody, &reqBody); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	attstnDoc, err := base64.StdEncoding.DecodeString(reqBody.Document)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.interimStateMutex.Lock()
	defer s.interimStateMutex.Unlock()

	if s.interimState == nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Verify attestation document and obtain its auxiliary information.
	aux, err := s.verifyAttstn(attstnDoc, s.interimState.nonce)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	leaderAux := aux.(*leaderAuxInfo)
	encrypted, err := base64.StdEncoding.DecodeString(reqBody.EncryptedKeys)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Make sure that the hash of the encrypted key material is present in the
	// attestation document.
	hash := sha256.Sum256(encrypted)
	if !bytes.Equal(hash[:], leaderAux.HashOfEncrypted) {
		http.Error(w, errHashNotInAttstn.Error(), http.StatusBadRequest)
		return
	}

	ephemeralKey := s.interimState.ephemeralKey
	s.interimState = nil
	// Decrypt the leader's enclave keys, which are encrypted with the
	// public key that we provided earlier.
	decrypted, ok := box.OpenAnonymous(
		nil,
		encrypted,
		ephemeralKey.pubKey,
		ephemeralKey.privKey)
	if !ok {
		http.Error(w, errFailedToDecrypt.Error(), http.StatusBadRequest)
		return
	}

	// Install the leader's enclave keys.
	if err := json.Unmarshal(decrypted, &keys); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.setupWorker(&keys); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		elog.Fatalf("Failed to install enclave keys: %v", err)
	}

	elog.Printf("Successfully synced keys %s with leader.", keys.hashAndB64())
}
