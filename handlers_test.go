package nitriding

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStateHandlers(t *testing.T) {
	expected := []byte{1, 2, 3, 4, 5} // The key material that we're setting and retrieving.
	e := createEnclave()
	setHandler := setStateHandler(e)
	getHandler := getStateHandler(e)
	rec := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodPut, pathState, bytes.NewReader(expected))
	if err != nil {
		t.Fatalf("Failed to create HTTP request: %v", err)
	}

	setHandler(rec, req)
	resp := rec.Result()

	// As long as we don't hit our (generous) upload limit, we always expect an
	// HTTP 200 response.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected HTTP status code %d but got %d.", http.StatusOK, resp.StatusCode)
	}

	// Now retrieve the state and make sure that it's what we sent earlier.
	req, err = http.NewRequest(http.MethodGet, pathState, nil)
	if err != nil {
		t.Fatalf("Failed to create HTTP request: %v", err)
	}
	rec = httptest.NewRecorder()
	getHandler(rec, req)
	resp = rec.Result()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected HTTP status code %d but got %d.", http.StatusOK, resp.StatusCode)
	}

	retrieved, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read HTTP response body: %v", err)
	}
	if !bytes.Equal(expected, retrieved) {
		t.Fatalf("Expected state %q but got %q.", expected, retrieved)
	}
}
