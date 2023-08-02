package main

import (
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// appRetrieverViaWeb installs a PUT endpoint that is used to upload the enclave
// application at runtime.
type appRetrieverViaWeb struct{}

func newAppRetrieverViaWeb() *appRetrieverViaWeb {
	return new(appRetrieverViaWeb)
}

func (l *appRetrieverViaWeb) retrieve(srv *http.Server, appChan chan []byte) error {
	srv.Handler.(*chi.Mux).Put(pathApp, func(w http.ResponseWriter, r *http.Request) {
		const maxAppLen = 1024 * 1024 * 50 // 50 MiB.

		app, err := io.ReadAll(newLimitReader(r.Body, maxAppLen))
		if err != nil {
			http.Error(w, errFailedReqBody.Error(), http.StatusInternalServerError)
			return
		}
		elog.Printf("Received %d-byte enclave application.", len(app))
		appChan <- app
		w.WriteHeader(http.StatusOK)
	})
	elog.Printf("Installed HTTP handler %s to receive enclave application.", pathApp)
	return nil
}
