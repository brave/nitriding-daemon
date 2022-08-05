package nitriding

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func expect(t *testing.T, resp *http.Response, statusCode int, errMsg string) {
	t.Helper()
	if errMsg == "" {
		return
	}
	payload, err := io.ReadAll(resp.Body)
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
	if resp.StatusCode != statusCode {
		t.Fatalf("expected status code %d but got %d", statusCode, resp.StatusCode)
	}
}

func testReq(t *testing.T, req *http.Request, statusCode int, errMsg string) {
	attestationHandler := getAttestationHandler(&[32]byte{})
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

func TestArePCRsIdentical(t *testing.T) {
	pcr1 := map[uint][]byte{
		1: []byte("foobar"),
	}
	pcr2 := map[uint][]byte{
		1: []byte("foobar"),
	}
	if !arePCRsIdentical(pcr1, pcr2) {
		t.Fatal("Failed to recognize identical PCRs as such.")
	}

	// Add a new PCR value, so our two maps are no longer identical.
	pcr1[2] = []byte("barfoo")
	if arePCRsIdentical(pcr1, pcr2) {
		t.Fatal("Failed to recognize different PCRs as such.")
	}

	// Add the same PCR ID but with a different value.
	pcr2[2] = []byte("foobar")
	if arePCRsIdentical(pcr1, pcr2) {
		t.Fatal("Failed to recognize different PCRs as such.")
	}
}
