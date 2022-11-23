package nitriding

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
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
	attestationHandler := attestationHandler(&AttestationHashes{})
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

func TestAttestationHashes(t *testing.T) {
	e := createEnclave()
	appKeyHash := [sha256.Size]byte{1, 2, 3, 4, 5}

	// Start the enclave.  This is going to initialize the hash over the HTTPS
	// certificate.
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	defer e.Stop() //nolint:errcheck
	signalReady(t, e)

	// Register dummy key material for the other hash to be initialized.
	rec := httptest.NewRecorder()
	buf := bytes.NewBufferString(base64.StdEncoding.EncodeToString(appKeyHash[:]))
	req := httptest.NewRequest(http.MethodPost, pathHash, buf)
	e.privSrv.Handler.ServeHTTP(rec, req)

	s := e.hashes.Serialize()
	expectedLen := sha256.Size*2 + len(hashPrefix)*2 + len(hashSeparator)
	if len(s) != expectedLen {
		t.Fatalf("Expected serialized hashes to be of length %d but got %d.",
			expectedLen, len(s))
	}

	// Make sure that the serialized slice starts with "sha256:".
	prefix := []byte(hashPrefix)
	if !bytes.Equal(s[:len(prefix)], prefix) {
		t.Fatalf("Expected prefix %s but got %s.", prefix, s[:len(prefix)])
	}

	// Make sure that our previously-set hash is as expected.
	expected := []byte(hashSeparator)
	expected = append(expected, []byte(hashPrefix)...)
	expected = append(expected, appKeyHash[:]...)
	offset := len(hashPrefix) + sha256.Size
	if !bytes.Equal(s[offset:], expected) {
		t.Fatalf("Expected application key hash of %x but got %x.", expected, s[offset:])
	}
}
