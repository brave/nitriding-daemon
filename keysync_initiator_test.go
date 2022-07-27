package nitriding

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

func TestRequestNonceDoS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce1 := nonce{}
		nonce2 := nonce{}
		fmt.Fprintf(w, "%s%s", nonce1.B64(), nonce2.B64())
	}))
	defer srv.Close()

	if _, err := requestNonce(srv.URL); err == nil {
		t.Fatal("Client code should have rejected long response body but didn't.")
	}
}

func TestRequestAttDoc(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "foobar")
	}))
	defer srv.Close()

	_, err := requestAttDoc(srv.URL, []byte{})
	if err == nil {
		t.Fatal("Client code should have rejected non-Base64 data but didn't.")
	}
}

func TestRequestAttDocDoS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		maxReadLen := base64.StdEncoding.EncodedLen(maxAttDocLen)
		buf := make([]byte, maxReadLen+1)
		fmt.Fprintln(w, buf)
	}))
	defer srv.Close()

	if _, err := requestAttDoc(srv.URL, []byte{}); err == nil {
		t.Fatal("Client code should have rejected long response body but didn't.")
	}
}

func TestProcessAttDoc(t *testing.T) {
	// The idea of this fairly involved test is to make sure that processAttDoc
	// can decrypt and recover the key material that's part of an attestation
	// document.  To that end, we are using a hard-coded attestation document,
	// NaCl key pair, and the PCR values of the attestation document.
	pubKey := [32]byte{
		213, 156, 108, 34, 179, 183, 69, 26, 209, 218, 58, 186, 9, 32, 237,
		253, 46, 80, 36, 200, 169, 239, 97, 200, 17, 188, 203, 99, 151, 40,
		10, 113,
	}
	privKey := [32]byte{
		74, 137, 121, 11, 209, 38, 48, 48, 167, 157, 184, 58, 2, 110, 9, 204,
		174, 148, 243, 154, 191, 74, 118, 90, 11, 240, 246, 131, 187, 157,
		157, 25,
	}
	ourNonce := nonce{}
	boxKey := boxKey{
		pubKey:  &pubKey,
		privKey: &privKey,
	}

	// Mock getPCRValues and make it return the PCR values that are in
	// responderAttDoc.
	null := make([]byte, 48) // An empty PCR value.
	getPCRValues = func() (map[uint][]byte, error) {
		return map[uint][]byte{
			0: []byte{
				0xb0, 0x61, 0xbc, 0xe3, 0x1a, 0x85, 0x50, 0xc2, 0x4c, 0xb8,
				0xc1, 0xdc, 0x0e, 0x53, 0x98, 0xe5, 0xc8, 0x0f, 0xab, 0xa6,
				0x7f, 0x75, 0xfd, 0x3b, 0x06, 0x21, 0xc0, 0xb8, 0x66, 0x36,
				0xfc, 0xe0, 0xd6, 0x4c, 0x4d, 0x7d, 0x37, 0x47, 0x89, 0x08,
				0xe1, 0xf8, 0xfc, 0xe9, 0xdf, 0x66, 0xe1, 0xb9},
			1: []byte{
				0xbc, 0xdf, 0x05, 0xfe, 0xfc, 0xca, 0xa8, 0xe5, 0x5b, 0xf2,
				0xc8, 0xd6, 0xde, 0xe9, 0xe7, 0x9b, 0xbf, 0xf3, 0x1e, 0x34,
				0xbf, 0x28, 0xa9, 0x9a, 0xa1, 0x9e, 0x6b, 0x29, 0xc3, 0x7e,
				0xe8, 0x0b, 0x21, 0x4a, 0x41, 0x4b, 0x76, 0x07, 0x23, 0x6e,
				0xdf, 0x26, 0xfc, 0xb7, 0x86, 0x54, 0xe6, 0x3f},
			2: []byte{
				0x6a, 0xe6, 0x79, 0x76, 0xd7, 0x40, 0x38, 0x0d, 0x50, 0x64,
				0x36, 0x91, 0xac, 0x3a, 0xae, 0xbb, 0xa6, 0x0f, 0x27, 0xd7,
				0xb8, 0xa0, 0xe1, 0xa9, 0xea, 0xf2, 0x38, 0x6d, 0x25, 0xee,
				0xab, 0x88, 0x1c, 0x09, 0xac, 0xc5, 0xc8, 0x09, 0xeb, 0xec,
				0xf9, 0x9b, 0x49, 0x71, 0x05, 0xf6, 0xcb, 0x5b},
			3: null,
			4: []byte{
				0xd8, 0xa8, 0xe8, 0xee, 0xe9, 0x6d, 0x81, 0xb7, 0x7a, 0x25,
				0x14, 0x10, 0xb7, 0xa9, 0xb1, 0x80, 0x78, 0x76, 0x53, 0xf1,
				0x25, 0xd1, 0xdb, 0xca, 0x79, 0x68, 0x5c, 0x93, 0xfb, 0x88,
				0x5b, 0x33, 0x5e, 0x0b, 0x8d, 0x17, 0x2c, 0x98, 0x21, 0xa8,
				0x62, 0x51, 0x5a, 0x60, 0x3c, 0xc3, 0x3a, 0xb2},
			5:  null,
			6:  null,
			7:  null,
			8:  null,
			9:  null,
			10: null,
			11: null,
			12: null,
			13: null,
			14: null,
			15: null,
		}, nil
	}

	validityTime, b64AttDoc := getResponderAttDoc()
	currentTime = func() time.Time { return validityTime }
	rawAttDoc, err := base64.StdEncoding.DecodeString(b64AttDoc)
	if err != nil {
		t.Fatalf("Failed to Base64-decode attestation document: %s", err)
	}

	keyMaterial := struct {
		SecretKey string `json:"secret_key"`
	}{}
	if err := processAttDoc(
		rawAttDoc,
		&ourNonce,
		&boxKey,
		&keyMaterial,
	); err != nil {
		t.Fatalf("Failed to verify valid attestation document: %s", err)
	}

	// Make sure that processAttDoc successfully decrypted and recovered the
	// secret key material, "foobar".
	if keyMaterial.SecretKey != "foobar" {
		t.Fatalf("Expected secret key 'foobar' but got %q.", keyMaterial.SecretKey)
	}
}
