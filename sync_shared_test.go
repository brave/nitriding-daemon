package main

import (
	"testing"
)

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
