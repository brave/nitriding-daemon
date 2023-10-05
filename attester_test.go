package main

import (
	"bytes"
	"errors"
	"testing"

	"github.com/hf/nitrite"
)

func TestDummyAttestation(t *testing.T) {
	var (
		d               = newDummyAttester()
		workersNonce    = nonce{1, 2, 3}
		hashOfEncrypted = []byte("this is a hash")
	)

	attstn, err := d.createAttstn(&leaderAuxInfo{
		WorkersNonce:    workersNonce,
		HashOfEncrypted: hashOfEncrypted,
	})
	failOnErr(t, err)

	aux, err := d.verifyAttstn(attstn, workersNonce)
	failOnErr(t, err)

	leaderAux := aux.(*leaderAuxInfo)
	if leaderAux.WorkersNonce != workersNonce {
		t.Fatal("Extracted unexpected workers nonce.")
	}
	if !bytes.Equal(leaderAux.HashOfEncrypted, hashOfEncrypted) {
		t.Fatalf("Extracted unexpected hash over encrypted keys.")
	}
}

func TestVerifyNitroAttstn(t *testing.T) {
	var n = newNitroAttester()
	_, err := n.verifyAttstn([]byte("foobar"), nonce{})
	assertEqual(t, errors.Is(err, nitrite.ErrBadCOSESign1Structure), true)
}

func TestCreateNitroAttstn(t *testing.T) {
	var n = newNitroAttester()
	_, err := n.createAttstn(nil)
	assertEqual(t, err != nil, true)
}
