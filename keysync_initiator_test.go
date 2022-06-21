package nitriding

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestNonce(t *testing.T) {
	expNonce := nonce{
		0x14, 0x56, 0x82, 0x13, 0x1f, 0xff, 0x9c, 0xf7, 0xeb, 0xb6,
		0x9e, 0x7b, 0xea, 0x29, 0x16, 0x49, 0xeb, 0x03, 0xa2, 0x47,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, expNonce.B64())
	}))
	defer srv.Close()

	retNonce, err := requestNonce(srv.URL)
	if err != nil {
		t.Fatalf("Failed to request nonce: %s", err)
	}
	if expNonce != retNonce {
		t.Fatal("Returned nonce not as expected.")
	}
}

func TestRequestAttDoc(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "foobar")
	}))
	defer srv.Close()

	_, err := requestAttDoc(srv.URL, []byte{})
	if err == nil {
		t.Fatal("should've failed")
	}
}
