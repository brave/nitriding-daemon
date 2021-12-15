package enclaveutils

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func expect(t *testing.T, resp *http.Response, statusCode int, errMsg string) {
	if resp.StatusCode != statusCode {
		t.Fatalf("expected status code %d but got %d", statusCode, resp.StatusCode)
	}
	if errMsg == "" {
		return
	}
	payload, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read HTTP response body: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("failed to close response body: %v", err)
		}
	}()
	if strings.TrimSuffix(string(payload), "\n") != errMsg {
		t.Fatalf("expected error %q but got %q", errMsg, string(payload))
	}
}

func testReq(t *testing.T, req *http.Request, statusCode int, errMsg string) {
	attestationHandler := getAttestationHandler([32]byte{})
	rec := httptest.NewRecorder()
	attestationHandler(rec, req)
	expect(t, rec.Result(), statusCode, errMsg)
}

func TestAttestationHandler(t *testing.T) {

	testReq(t,
		httptest.NewRequest(http.MethodPost, "/attestation", nil),
		http.StatusMethodNotAllowed,
		"",
	)

	testReq(t,
		httptest.NewRequest(http.MethodGet, "/attestation", nil),
		http.StatusBadRequest,
		errNoNonce,
	)

	testReq(t,
		httptest.NewRequest(http.MethodGet, "/attestation?nonce=foobar", nil),
		http.StatusBadRequest,
		errBadNonceFormat,
	)

	// We are unable to test the successful issuing of an attestation document
	// on a non-Nitro system.
}
