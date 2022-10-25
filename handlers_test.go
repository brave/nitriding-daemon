package nitriding

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetRegisterKeysHandler(t *testing.T) {
	expected := []byte{1, 2, 3, 4, 5} // The key material that we're setting and retrieving.
	e := createEnclave()
	handler := getSetKeysHandler(e)
	rec := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodPut, pathPostKeys, bytes.NewReader(expected))
	if err != nil {
		t.Fatalf("Failed to create HTTP request: %v", err)
	}

	handler(rec, req)
	resp := rec.Result()

	// As long as we don't hit our (generous) upload limit, we always expect an
	// HTTP 200 response.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected HTTP status code %d but got %d.", http.StatusOK, resp.StatusCode)
	}

	// Make sure that the key material was set in the enclave.
	m, err := e.KeyMaterial()
	if err != nil {
		t.Fatalf("Failed to obtain enclave key material: %v", err)
	}
	retrieved := m.([]byte)

	if !bytes.Equal(retrieved, expected) {
		t.Fatalf("Expected %q but got %q.", expected, retrieved)
	}
}
