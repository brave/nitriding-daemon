package nitriding

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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
	errHashWrongSize  = errors.New("given hash is of invalid size")
)

func formatIndexPage(appURL string) string {
	page := indexPage
	if appURL != "" {
		page += fmt.Sprintf("\nIt runs the following code: %s\n"+
			"Use the following tool to verify the enclave: "+
			"https://github.com/brave-experiments/verify-enclave", appURL)
	}
	return page
}

// getIndexHandler returns an index handler that informs the visitor that this
// host runs inside an enclave.
func getIndexHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, formatIndexPage(cfg.AppURL))
	}
}

// syncHandler returns a handler that lets the enclave application trigger
// state synchronization, which copies the given remote enclave's state into
// our state.
func syncHandler(e *Enclave) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		// The 'addr' parameter must have the following form:
		// https://example.com:8443
		addrs, ok := q["addr"]
		if !ok {
			http.Error(w, errNoAddr.Error(), http.StatusBadRequest)
			return
		}
		addr := addrs[0]

		// Are we dealing with a well-formed URL?
		if _, err := url.Parse(addr); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := RequestKeys(addr, e.KeyMaterial); err != nil {
			http.Error(w, fmt.Sprintf("failed to synchronize state: %v", err), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// getStateHandler returns a handler that lets the enclave application retrieve
// previously-set state.
func getStateHandler(e *Enclave) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		s, err := e.KeyMaterial()
		if err != nil {
			http.Error(w, errFailedGetState.Error(), http.StatusInternalServerError)
			return
		}
		n, err := w.Write(s.([]byte))
		if err != nil {
			elog.Printf("Error writing state to client: %v", err)
			return
		}
		expected := len(s.([]byte))
		if n != expected {
			elog.Printf("Only wrote %d out of %d-byte state to client.", n, expected)
			return
		}
	}
}

// setStateHandler returns a handler that lets the enclave application set
// state that's synchronized with another enclave in case of horizontal
// scaling.  The state can be arbitrary bytes.
func setStateHandler(e *Enclave) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(newLimitReader(r.Body, maxKeyMaterialLen))
		if err != nil {
			http.Error(w, errFailedReqBody.Error(), http.StatusInternalServerError)
			return
		}
		e.SetKeyMaterial(body)
		w.WriteHeader(http.StatusOK)
	}
}

// proxyHandler returns an HTTP handler that proxies HTTP requests to the
// enclave-internal HTTP server of our enclave application.
func proxyHandler(e *Enclave) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		e.revProxy.ServeHTTP(w, r)
	}
}

// keyHandler returns an HTTP handler that allows the enclave application to
// register a hash over a public key which is going to be included in
// attestation documents.  This allows clients to tie the attestation document
// (which acts as the root of trust) to key material that's used by the enclave
// application.
func keyHandler(e *Enclave) http.HandlerFunc {
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
