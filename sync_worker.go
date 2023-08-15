package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/nacl/box"
)

var (
	errBecameLeader    = errors.New("became enclave leader")
	errNonceRequired   = errors.New("nonce is required")
	errInProgress      = errors.New("key sync already in progress")
	errInvalidNonceLen = errors.New("invalid nonce length")
	errDecrypting      = errors.New("error decrypting enclave keys")
)

// workerSync holds the state and code that we need for a one-off sync with a
// leader enclave.  workerSync implements the http.Handler interface because the
// sync protocol requires two endpoints on the worker.
type workerSync struct {
	attester
	installKeys   func(*enclaveKeys) error
	ephemeralKeys chan *boxKey
	nonce         chan nonce
	becameLeader  chan struct{}
}

// asWorker returns a new workerSync object.
func asWorker(
	installKeys func(*enclaveKeys) error,
	becameLeader chan struct{},
) *workerSync {
	return &workerSync{
		attester:      &dummyAttester{},
		installKeys:   installKeys,
		becameLeader:  becameLeader,
		nonce:         make(chan nonce, 1),
		ephemeralKeys: make(chan *boxKey, 1),
	}
}

// registerWith registers the worker with the given leader enclave.
func (s *workerSync) registerWith(leader *url.URL) error {
	elog.Println("Attempting to sync with leader.")

	errChan := make(chan error)
	register := func(e chan error) {
		resp, err := newUnauthenticatedHTTPClient().Post(leader.String(), "text/plain", nil)
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
		case <-s.becameLeader:
			elog.Println("We became leader. Aborting key sync.")
			return errBecameLeader
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

	// There must not be more than one key synchronization attempt at any given
	// time.  Abort if we get another request while key synchronization is still
	// in progress.
	if len(s.ephemeralKeys) > 0 {
		http.Error(w, errInProgress.Error(), http.StatusTooManyRequests)
		return
	}

	// Extract the leader's nonce from the URL, which must look like this:
	// https://example.com/enclave/sync?nonce=[HEX-ENCODED-NONCE]
	hexNonce := r.URL.Query().Get("nonce")
	if hexNonce == "" {
		http.Error(w, errNonceRequired.Error(), http.StatusBadRequest)
		return
	}
	nonceSlice, err := hex.DecodeString(hexNonce)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(nonceSlice) != nonceLen {
		http.Error(w, errInvalidNonceLen.Error(), http.StatusBadRequest)
		return
	}
	var leadersNonce nonce
	copy(leadersNonce[:], nonceSlice)

	// Create the worker's nonce and store it in our channel, so we can later
	// verify it.
	workersNonce, err := newNonce()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.nonce <- workersNonce

	// Create an ephemeral key that the leader is going to use to encrypt
	// its enclave keys.
	boxKey, err := newBoxKey()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.ephemeralKeys <- boxKey

	// Create and return the worker's Base64-encoded attestation document.
	aux := &workerAuxInfo{
		WorkersNonce: workersNonce,
		LeadersNonce: leadersNonce,
		PublicKey:    boxKey.pubKey[:],
	}
	attstn, err := s.createAttstn(aux)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, base64.StdEncoding.EncodeToString(attstn))
}

// finishSync responds to the leader's final request before key synchronization
// is complete.
func (s *workerSync) finishSync(w http.ResponseWriter, r *http.Request) {
	elog.Println("Received leader's request to complete key sync.")

	// Read the leader's Base64-encoded attestation document.
	maxReadLen := base64.StdEncoding.EncodedLen(maxAttDocLen)
	b64Attstn, err := io.ReadAll(newLimitReader(r.Body, maxReadLen))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Decode Base64 to byte slice.
	attstn, err := base64.StdEncoding.DecodeString(string(b64Attstn))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	aux, err := s.verifyAttstn(attstn, <-s.nonce)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ephemeralKey := <-s.ephemeralKeys
	// Decrypt the leader's enclave keys, which are encrypted with the
	// public key that we provided earlier.
	decrypted, ok := box.OpenAnonymous(
		nil,
		aux.(*leaderAuxInfo).EnclaveKeys,
		ephemeralKey.pubKey,
		ephemeralKey.privKey)
	if !ok {
		http.Error(w, errDecrypting.Error(), http.StatusBadRequest)
		return
	}

	// Install the leader's enclave keys.
	var keys enclaveKeys
	if err := json.Unmarshal(decrypted, &keys); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.installKeys(&keys)

	elog.Println("Successfully synced with leader.")
}
