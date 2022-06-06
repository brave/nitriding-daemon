package nitriding

import (
	"fmt"
	"net/http"
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
