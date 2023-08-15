package main

import (
	"crypto/rand"
	"errors"
	"testing"
)

func failOnErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestBoxKeyRandomness(t *testing.T) {
	k1, err := newBoxKey()
	failOnErr(t, err)
	k2, err := newBoxKey()
	failOnErr(t, err)

	// It's notoriously difficult to test if something is truly random.  Here,
	// we simply make sure that two subsequently generated key pairs are not
	// identical.  That's a low bar to pass but better than nothing.
	if k1.privKey == k2.privKey {
		t.Error("Private keys of two separate box keys are identical.")
	}
	if k1.pubKey == k2.pubKey {
		t.Error("Public keys of two separate box keys are identical.")
	}
}

func TestNonce(t *testing.T) {
	n1, err := newNonce()
	failOnErr(t, err)
	n2, err := newNonce()
	failOnErr(t, err)

	if n1 == n2 {
		t.Error("Two separately generated nonces are identical.")
	}
	if n1.B64() == n2.B64() {
		t.Error("Two separately generated Base64-encoded nonces are identical.")
	}
}

func TestErrors(t *testing.T) {
	// Make cryptoRead always return an error, and check if functions propagate
	// that error.
	ourError := errors.New("not enough randomness")
	cryptoRead = func(b []byte) (n int, err error) {
		return 0, ourError
	}
	defer func() {
		cryptoRead = rand.Read
	}()

	if _, err := newNonce(); err == nil {
		t.Error("Failed to return error")
		if !errors.Is(err, ourError) {
			t.Error("Propagated error does not contain expected error string.")
		}
	}
}
