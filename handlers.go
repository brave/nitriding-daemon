package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

const (
	// The maximum length of the key material (in bytes) that enclave
	// applications can PUT to our HTTP API.
	maxKeyMaterialLen = 1024 * 1024
	// The maximum length (in bytes) of a heartbeat's request body:
	// 44 bytes for the Base64-encoded SHA-256 hash, 255 bytes for the domain
	// name, and another 128 bytes for the port and the surrounding JSON.
	maxHeartbeatBody = 44 + 255 + 128
	// The HTML for the enclave's index page.
	indexPage = "This host runs inside an AWS Nitro Enclave.\n"
)

var (
	errFailedReqBody         = errors.New("failed to read request body")
	errHashWrongSize         = errors.New("given hash is of invalid size")
	errNoBase64              = errors.New("no Base64 given")
	errDesignationInProgress = errors.New("leader designation in progress")
	errEndpointGone          = errors.New("endpoint not meant to be used")
	errKeySyncDisabled       = errors.New("key synchronization is disabled")
)

func errNo200(code int) error {
	return fmt.Errorf("peer responded with HTTP code %d", code)
}

func formatIndexPage(appURL *url.URL) string {
	page := indexPage
	if appURL != nil {
		page += fmt.Sprintf("\nIt runs the following code: %s\n"+
			"Use the following tool to verify the enclave: "+
			"https://github.com/brave-experiments/verify-enclave", appURL.String())
	}
	return page
}

// rootHandler returns a handler that informs the visitor that this host runs
// inside an enclave.  This is useful for testing.
func rootHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, formatIndexPage(cfg.AppURL))
	}
}

// putStateHandler returns a handler that lets the enclave application set
// state that's synchronized with another enclave in case of horizontal
// scaling.  The state can be arbitrary bytes.
//
// This is an enclave-internal endpoint that can only be accessed by the
// trusted enclave application.
func putStateHandler(
	a attester,
	getSyncState func() int,
	enclaveKeys *enclaveKeys,
	workers *workerManager,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch getSyncState() {
		case noSync:
			http.Error(w, errKeySyncDisabled.Error(), http.StatusForbidden)
		case isWorker:
			http.Error(w, errEndpointGone.Error(), http.StatusGone)
		case inProgress:
			http.Error(w, errDesignationInProgress.Error(), http.StatusServiceUnavailable)
		case isLeader:
			keys, err := io.ReadAll(newLimitReader(r.Body, maxKeyMaterialLen))
			if err != nil {
				http.Error(w, errFailedReqBody.Error(), http.StatusInternalServerError)
				return
			}
			enclaveKeys.setAppKeys(keys)
			w.WriteHeader(http.StatusOK)

			// The leader's application keys have changed.  Re-synchronize the key
			// material with all registered workers.  If synchronization fails for a
			// given worker, unregister it.
			elog.Printf("Application keys have changed.  Re-synchronizing with %d worker(s).",
				workers.length())
			go workers.forAll(
				func(worker *url.URL) {
					if err := asLeader(enclaveKeys, a).syncWith(worker); err != nil {
						workers.unregister(worker)
					}
				},
			)
		}
	}
}

// hashHandler returns an HTTP handler that allows the enclave application to
// register a hash over a public key which is going to be included in
// attestation documents.  This allows clients to tie the attestation document
// (which acts as the root of trust) to key material that's used by the enclave
// application.
//
// This is an enclave-internal endpoint that can only be accessed by the
// trusted enclave application.
func hashHandler(e *Enclave) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Allow an extra byte for the \n.
		maxReadLen := base64.StdEncoding.EncodedLen(sha256.Size) + 1
		body, err := io.ReadAll(newLimitReader(r.Body, maxReadLen))
		if errors.Is(err, errTooMuchToRead) {
			http.Error(w, errTooMuchToRead.Error(), http.StatusBadRequest)
			return
		}
		if err != nil {
			http.Error(w, errFailedReqBody.Error(), http.StatusInternalServerError)
		}

		keyHash, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
		if err != nil {
			http.Error(w, errNoBase64.Error(), http.StatusBadRequest)
			return
		}

		if len(keyHash) != sha256.Size {
			http.Error(w, errHashWrongSize.Error(), http.StatusBadRequest)
			return
		}
		copy(e.hashes.appKeyHash[:], keyHash)
	}
}

// readyHandler returns an HTTP handler that lets the enclave application
// signal that it's ready, instructing nitriding to start its Internet-facing
// Web server.  We initially gate access to the Internet-facing API to avoid
// the issuance of unexpected attestation documents that lack the application's
// hash because the application couldn't register it in time.
//
// This is an enclave-internal endpoint that can only be accessed by the
// trusted enclave application.
func readyHandler(ready chan struct{}) http.HandlerFunc {
	var once sync.Once
	return func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() {
			close(ready)
			w.WriteHeader(http.StatusOK)
		})
		w.WriteHeader(http.StatusGone)
	}
}

// configHandler returns an HTTP handler that prints the enclave's
// configuration.
func configHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, cfg)
	}
}

// attestationHandler takes as input a flag indicating if profiling is enabled
// and an AttestationHashes struct, and returns a HandlerFunc.  If profiling is
// enabled, we abort attestation because profiling leaks enclave-internal data.
// The returned HandlerFunc expects a nonce in the URL query parameters and
// subsequently asks its hypervisor for an attestation document that contains
// both the nonce and the hashes in the given struct.  The resulting
// Base64-encoded attestation document is then returned to the requester.
func attestationHandler(useProfiling bool, hashes *AttestationHashes, a attester) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if useProfiling {
			http.Error(w, errProfilingSet.Error(), http.StatusServiceUnavailable)
			return
		}

		n, err := getNonceFromReq(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		rawDoc, err := a.createAttstn(&clientAuxInfo{
			clientNonce:       n,
			attestationHashes: hashes.Serialize(),
		})
		if err != nil {
			http.Error(w, errFailedAttestation.Error(), http.StatusInternalServerError)
			return
		}
		b64Doc := base64.StdEncoding.EncodeToString(rawDoc)
		fmt.Fprintln(w, b64Doc)
	}
}

func heartbeatHandler(e *Enclave) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			hb              heartbeatRequest
			syncAndRegister = func(keys *enclaveKeys, worker *url.URL) {
				if err := asLeader(keys, e.attester).syncWith(worker); err == nil {
					e.workers.register(worker)
				}
			}
		)

		body, err := io.ReadAll(newLimitReader(r.Body, maxHeartbeatBody))
		if err != nil {
			http.Error(w, errFailedReqBody.Error(), http.StatusInternalServerError)
			return
		}
		if err := json.Unmarshal(body, &hb); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		worker, err := e.getWorker(&hb)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		elog.Printf("Heartbeat from worker %s.", worker.Host)
		ourKeysHash, theirKeysHash := e.keys.hashAndB64(), hb.HashedKeys
		if ourKeysHash != theirKeysHash {
			elog.Printf("Worker's keys are invalid.  Re-synchronizing.")
			go syncAndRegister(e.keys, worker)
		} else {
			e.workers.register(worker)
		}
		w.WriteHeader(http.StatusOK)
	}
}

func getLeaderHandler(ourNonce nonce, weAreLeader chan struct{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			err        error
			theirNonce nonce
		)
		theirNonce, err = getNonceFromReq(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if ourNonce == theirNonce {
			if len(weAreLeader) == 0 {
				weAreLeader <- struct{}{}
			}
		} else {
			// We may end up in this branch for two reasons:
			// 1. We're the leader and a worker beat us to talking to this
			//    endpoint.
			// 2. We're a worker and some other entity in the private network is
			//    talking to this endpoint.  That shouldn't happen.
			elog.Println("Received nonce that does not match our own.")
		}
		w.WriteHeader(http.StatusOK)
	}
}
