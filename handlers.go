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
	errFailedReqBody = errors.New("failed to read request body")
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

// getSetKeysHandler returns a handler that lets the enclave application
// register its key material with nitriding.  The key material can be arbitrary
// bytes.
func getSetKeysHandler(e *Enclave) http.HandlerFunc {
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
