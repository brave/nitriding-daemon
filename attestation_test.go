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
	// Helper to create a PCR map with all identity PCRs set to the same value.
	makePCRs := func(val []byte) map[uint][]byte {
		m := make(map[uint][]byte)
		for _, pcr := range identityPCRs {
			m[pcr] = append([]byte{}, val...)
		}
		return m
	}

	pcr1 := makePCRs([]byte("foobar"))
	pcr2 := makePCRs([]byte("foobar"))
	if !arePCRsIdentical(pcr1, pcr2) {
		t.Fatal("Failed to recognize identical PCRs as such.")
	}

	// All non-identity PCRs (0–31) should be ignored, even when they differ
	// between the two maps.
	isIdentityPCR := make(map[uint]bool)
	for _, pcr := range identityPCRs {
		isIdentityPCR[pcr] = true
	}
	for i := uint(0); i < 32; i++ {
		if isIdentityPCR[i] {
			continue
		}
		pcr1[i] = []byte("foo")
		pcr2[i] = []byte("bar")
	}
	if !arePCRsIdentical(pcr1, pcr2) {
		t.Fatal("Non-identity PCRs should be ignored.")
	}

	// Changing an identity PCR should cause a mismatch.
	pcr1[2] = []byte("different")
	if arePCRsIdentical(pcr1, pcr2) {
		t.Fatal("Failed to recognize different PCRs as such.")
	}

	// A missing identity PCR in one map should cause a mismatch.
	delete(pcr1, 2)
	if arePCRsIdentical(pcr1, pcr2) {
		t.Fatal("Failed to recognize missing PCR as mismatch.")
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
	e.intSrv.Handler.ServeHTTP(rec, req)

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
