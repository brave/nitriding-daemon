package main

import (
	"crypto/rand"
	"errors"
	"testing"
)

func failOnErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Expected no error but got %v.", err)
	}
}

func TestNonce(t *testing.T) {
	nonce1, err := newNonce()
	failOnErr(t, err)
	nonce2, err := newNonce()
	failOnErr(t, err)

	if nonce1 == nonce2 {
		t.Fatal("Two separate nonces should not be identical.")
	}
	if nonce1.b64() == nonce2.b64() {
		t.Fatal("Two separate, Base64-encoded nonces should not be identical.")
	}
}

func TestNonceErrors(t *testing.T) {
	defer func() {
		cryptoRead = rand.Read
	}()

	// Make cryptoRead return an error.
	ourError := errors.New("not enough randomness")
	cryptoRead = func(b []byte) (n int, err error) {
		return 0, ourError
	}
	if _, err := newNonce(); !errors.Is(err, ourError) {
		t.Fatal("Propagated error does not contain expected error string.")
	}

	// Make cryptoRead return an insufficient number of random bytes.
	cryptoRead = func(b []byte) (n int, err error) {
		return nonceLen - 1, nil
	}
	if _, err := newNonce(); !errors.Is(err, errNotEnoughRead) {
		t.Fatalf("Expected error %v but got %v.", errNotEnoughRead, err)
	}
}
