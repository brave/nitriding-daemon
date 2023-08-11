package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/nacl/box"
)

const (
	// The maximum length of the key material (in bytes) that enclave
	// applications can PUT to our HTTP API.
	maxKeyMaterialLen = 1024 * 1024
	// The HTML for the enclave's index page.
	indexPage = "This host runs inside an AWS Nitro Enclave.\n"
)

var (
	errFailedReqBody  = errors.New("failed to read request body")
	errFailedGetState = errors.New("failed to retrieve saved state")
	errNoAddr         = errors.New("parameter 'addr' not found")
	errBadSyncAddr    = errors.New("invalid 'addr' parameter for sync")
	errHashWrongSize  = errors.New("given hash is of invalid size")
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

// reqSyncHandler returns a handler that lets the enclave application request
// state synchronization, which copies the given remote enclave's state into
// our state.
//
// This is an enclave-internal endpoint that can only be accessed by the
// trusted enclave application.
//
// FIXME: https://github.com/brave/nitriding-daemon/issues/10
func reqSyncHandler(e *Enclave) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		// The 'addr' parameter must have the following form:
		// https://example.com:443
		addrs, ok := q["addr"]
		if !ok {
			http.Error(w, errNoAddr.Error(), http.StatusBadRequest)
			return
		}
		addr := addrs[0]

		// Are we dealing with a well-formed URL?
		if _, err := url.Parse(addr); err != nil {
			http.Error(w, errBadSyncAddr.Error(), http.StatusBadRequest)
			return
		}

		if err := RequestKeys(addr, e.AppKeys); err != nil {
			http.Error(w, fmt.Sprintf("failed to synchronize state: %v", err), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
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
		keys, err := e.AppKeys()
		if err != nil {
			http.Error(w, errFailedGetState.Error(), http.StatusInternalServerError)
			return
		}
		n, err := w.Write(keys)
		if err != nil {
			elog.Printf("Error writing state to client: %v", err)
			return
		}
		expected := len(keys)
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
		e.SetAppKeys(keys)
		w.WriteHeader(http.StatusOK)

		// The leader's application keys have changed.  Re-synchronize the key
		// material with all registered workers.  If synchronization fails for a
		// given worker, unregister it.
		for worker := range e.workers.set {
			go func(worker *url.URL) {
				if err := e.syncWithWorker(worker); err != nil {
					// TODO: Log in Prometheus.
					// TODO: We may want to re-attempt synchronization.
					elog.Printf("Error syncing with worker %s: %v", worker.String(), err)
					e.workers.unregister(worker)
				} else {
					elog.Printf("Successfully synced with worker %s.", worker.String())
				}
			}(&worker)
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
func attestationHandler(useProfiling bool, hashes *AttestationHashes) http.HandlerFunc {
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

		rawDoc, err := attest(rawNonce, hashes.Serialize(), nil)
		if err != nil {
			http.Error(w, errFailedAttestation, http.StatusInternalServerError)
			return
		}
		b64Doc := base64.StdEncoding.EncodeToString(rawDoc)
		fmt.Fprintln(w, b64Doc)
	}
}

func leaderHandler(e *Enclave) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		elog.Println("Designated enclave as leader.")
		close(e.isLeader) // Signal to other parts of the code.

		e.extPrivSrv.Handler.(*chi.Mux).Post(pathRegistration, workerRegistrationHandler(e))
		elog.Println("Set up worker registration endpoint.")

		w.WriteHeader(http.StatusOK)
	}
}

func workerRegistrationHandler(e *Enclave) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Go's HTTP server sets RemoteAddr to IP:port:
		// https://pkg.go.dev/net/http#Request
		strIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "error extracting IP address", http.StatusInternalServerError)
			return
		}
		worker := &url.URL{
			Scheme: "https",
			Host:   fmt.Sprintf("%s:%d", strIP, 9444), // TODO: Use e.cfg.ExtPrivPort.
			Path:   pathSync,
		}
		w.WriteHeader(http.StatusOK)

		go func() {
			if err := e.syncWithWorker(worker); err != nil {
				elog.Printf("Error syncing with worker %s: %v", worker.String(), err)
				return
			}
			e.workers.register(worker)
			elog.Printf("Successfully registered and synced with worker %s.", worker.String())
		}()
	}
}

const errNonceRequired = "nonce is required"

func heartbeatHandler(keys *enclaveKeys) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, keys.hashAndB64())
		// e.workers.updateAndPrune() // TODO
	}
}

// TODO: Terminate worker if sync fails.
func initSyncHandler(e *Enclave) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		elog.Println("New request to init key sync.")

		// Extract the leader's nonce from the URL.
		hexNonce := r.URL.Query().Get("nonce")
		if hexNonce == "" {
			http.Error(w, errNonceRequired, http.StatusBadRequest)
			return
		}

		nonceSlice, err := hex.DecodeString(hexNonce)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(nonceSlice) != nonceLen {
			http.Error(w, "invalid nonce length", http.StatusBadRequest)
			return
		}
		var leadersNonce nonce
		copy(leadersNonce[:], nonceSlice)

		// Create the worker's nonce and add it to our nonce cache, so it can
		// later be verified.
		workersNonce, err := newNonce()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		e.nonceCache.Add(workersNonce.B64())

		// Create an ephemeral key that the leader is going to use to encrypt
		// its enclave keys.
		boxKey, err := newBoxKey()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		e.ephemeralSyncKeys = boxKey // TODO: Could be more elegant.

		// Create and return the worker's Base64-encoded attestation document.
		aux := &workerAuxInfo{
			WorkersNonce: workersNonce,
			LeadersNonce: leadersNonce,
			PublicKey:    boxKey.pubKey[:],
		}
		attstn, err := e.createAttstn(aux)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Fprintln(w, base64.StdEncoding.EncodeToString(attstn))
	}
}

// TODO: Terminate worker if sync fails.
// finishSyncHandler is called by the leader to finish key synchronization.
func finishSyncHandler(e *Enclave) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		elog.Println("New request to finish key sync.")

		// Read the leader's Base64-encoded attestation document.
		maxReadLen := base64.StdEncoding.EncodedLen(maxAttDocLen)
		b64Attstn, err := io.ReadAll(newLimitReader(r.Body, maxReadLen))
		if err != nil {
			elog.Printf("Failed to read http body: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		elog.Printf("Leader's attstn doc: %v", string(b64Attstn))

		// Decode Base64 to byte slice.
		attstn, err := base64.StdEncoding.DecodeString(string(b64Attstn))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		aux, err := e.verifyAttstn(attstn, e.nonceCache.Exists)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Decrypt the leader's enclave keys, which are encrypted with the
		// public key that we provided earlier.
		decrypted, ok := box.OpenAnonymous(
			nil,
			aux.(*leaderAuxInfo).EnclaveKeys,
			e.ephemeralSyncKeys.pubKey,
			e.ephemeralSyncKeys.privKey)
		if !ok {
			http.Error(w, "error decrypting enclave keys", http.StatusBadRequest)
			return
		}
		e.ephemeralSyncKeys = nil // Clear the ephemeral key material.

		// Set the leader's enclave keys.
		var keys enclaveKeys
		if err := json.Unmarshal(decrypted, &keys); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		cert, err := tls.X509KeyPair(keys.NitridingCert, keys.NitridingKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		e.httpsCert.set(&cert)

		elog.Printf("Leader's enclave keys: %s (%s)", string(decrypted), decrypted)
	}
}
