package nitriding

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

const (
	// The maximum length of the key material (in bytes) that enclave
	// applications can PUT to our HTTP API.
	maxKeyMaterialLen = 1024 * 1024
)

var (
	errFailedReqBody  = errors.New("failed to read request body")
	errFailedGetState = errors.New("failed to retrieve saved state")
)

func formatIndexPage(appURL string) string {
	page := "This host runs inside an AWS Nitro Enclave.\n"
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
