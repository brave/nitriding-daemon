package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
	e := createEnclave(&defaultCfg)
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
	expectedLen := sha256.Size*2 + len(hashPrefix)*2
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
	expected := []byte(hashPrefix)
	expected = append(expected, appKeyHash[:]...)
	offset := len(hashPrefix) + sha256.Size
	if !bytes.Equal(s[offset:], expected) {
		t.Fatalf("Expected application key hash of %x but got %x.", expected, s[offset:])
	}
}
