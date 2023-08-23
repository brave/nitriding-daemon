package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
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
	errFailedReqBody = errors.New("failed to read request body")
	errHashWrongSize = errors.New("given hash is of invalid size")
	errNoBase64      = errors.New("no Base64 given")
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

// getStateHandler returns a handler that lets the enclave application retrieve
// previously-set state.
//
// This is an enclave-internal endpoint that can only be accessed by the
// trusted enclave application.
func getStateHandler(e *Enclave) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		appKeys := e.keys.getAppKeys()
		n, err := w.Write(appKeys)
		if err != nil {
			elog.Printf("Error writing state to client: %v", err)
			return
		}
		expected := len(appKeys)
		if n != expected {
			elog.Printf("Only wrote %d out of %d-byte state to client.", n, expected)
			return
		}
	}
}

// putStateHandler returns a handler that lets the enclave application set
// state that's synchronized with another enclave in case of horizontal
// scaling.  The state can be arbitrary bytes.
//
// This is an enclave-internal endpoint that can only be accessed by the
// trusted enclave application.
func putStateHandler(e *Enclave) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		keys, err := io.ReadAll(newLimitReader(r.Body, maxKeyMaterialLen))
		if err != nil {
			http.Error(w, errFailedReqBody.Error(), http.StatusInternalServerError)
			return
		}
		e.keys.setAppKeys(keys)
		w.WriteHeader(http.StatusOK)

		// The leader's application keys have changed.  Re-synchronize the key
		// material with all registered workers.  If synchronization fails for a
		// given worker, unregister it.
		elog.Printf("Application keys have changed.  Re-synchronizing with %d worker(s).",
			e.workers.length())
		go e.workers.forAll(
			func(worker *url.URL) {
				if err := asLeader(e.keys.get()).syncWith(worker); err != nil {
					e.workers.unregister(worker)
				}
			},
		)
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
// hash because the application couldn't register it in time.  The downside is
// that state synchronization among enclaves does not work until the
// application signalled its readiness.  While not ideal, we chose to ignore
// this for now.
//
// This is an enclave-internal endpoint that can only be accessed by the
// trusted enclave application.
func readyHandler(e *Enclave) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		close(e.ready)
		w.WriteHeader(http.StatusOK)
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
			http.Error(w, errProfilingSet, http.StatusServiceUnavailable)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, errBadForm, http.StatusBadRequest)
			return
		}

		nonce := r.URL.Query().Get("nonce")
		if nonce == "" {
			http.Error(w, errNoNonce, http.StatusBadRequest)
			return
		}
		nonce = strings.ToLower(nonce)
		// Decode hex-encoded nonce.
		rawNonce, err := hex.DecodeString(nonce)
		if err != nil {
			http.Error(w, errBadNonceFormat, http.StatusBadRequest)
			return
		}

		n, err := sliceToNonce(rawNonce)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		rawDoc, err := a.createAttstn(&clientAuxInfo{
			clientNonce:       n,
			attestationHashes: hashes.Serialize(),
		})
		if err != nil {
			http.Error(w, errFailedAttestation, http.StatusInternalServerError)
			return
		}
		b64Doc := base64.StdEncoding.EncodeToString(rawDoc)
		fmt.Fprintln(w, b64Doc)
	}
}

// leaderHandler is called when the enclave is designated as leader enclave.
// If designated, we do the following:
//
//  1. Signal to our leader registration goroutine that we're the leader.
//  2. Start the worker event loop, to keep track of worker enclaves.
//  3. Expose leader-specific endpoints.
func leaderHandler(ctx context.Context, e *Enclave) http.HandlerFunc {
	var once sync.Once
	return func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() {
			e.becameLeader <- struct{}{}
			go e.workers.start(ctx)
			// Make leader-specific endpoints available.
			e.intSrv.Handler.(*chi.Mux).Put(pathState, putStateHandler(e))
			e.extPrivSrv.Handler.(*chi.Mux).Post(pathHeartbeat, heartbeatHandler(e))
			elog.Println("Designated enclave as leader.")
		})
		w.WriteHeader(http.StatusOK)
	}
}

func heartbeatHandler(e *Enclave) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			hb              heartbeatRequest
			syncAndRegister = func(keys *enclaveKeys, worker *url.URL) {
				if err := asLeader(keys.get()).syncWith(worker); err == nil {
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
		worker, err := e.getWorker(r, &hb)
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
