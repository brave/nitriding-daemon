package nitriding

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func createEnclave() *Enclave {
	cfg := &Config{
		SOCKSProxy: "socks5://127.0.0.1:1080",
		FQDN:       "example.com",
		Port:       50000,
		UseACME:    false,
		Debug:      false,
		FdCur:      1024,
		FdMax:      4096,
	}
	return NewEnclave(cfg)
}

func TestGenSelfSignedCert(t *testing.T) {
	e := createEnclave()
	if err := e.genSelfSignedCert(); err != nil {
		t.Fatalf("Failed to create self-signed certificate: %s", err)
	}
}

func TestAddRoute(t *testing.T) {
	pathFoo := "/foo"
	expectedBody := "foo"
	handler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, expectedBody)
	}

	e := createEnclave()
	e.AddRoute(http.MethodGet, pathFoo, handler)

	req := httptest.NewRequest(http.MethodGet, pathFoo, nil)
	w := httptest.NewRecorder()
	handler(w, req)

	resp := w.Result()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %s", err)
	}
	if string(body) != expectedBody {
		t.Fatalf("Expected body %q but got %q.", expectedBody, string(body))
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code %d but got %d.", http.StatusOK, resp.StatusCode)
	}
}

func TestKeyMaterial(t *testing.T) {
	e := createEnclave()
	k := struct{ Foo string }{"foobar"}

	if _, err := e.KeyMaterial(); err == nil {
		t.Fatal("Expected error because we're trying to retrieve non-existing key material.")
	}

	e.SetKeyMaterial(k)
	r, err := e.KeyMaterial()
	if err != nil {
		t.Fatalf("Failed to retrieve key material: %s", err)
	}
	if r != k {
		t.Fatal("Retrieved key material is unexpected.")
	}
}
