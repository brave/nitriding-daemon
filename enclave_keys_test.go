package main

import (
	"bytes"
	"testing"
)

// newTestKeys returns arbitrary keys that we use for testing.
func newTestKeys(t *testing.T) *enclaveKeys {
	t.Helper()
	var testKeys = &enclaveKeys{
		AppKeys: []byte("AppTestKeys"),
	}
	cert, key, err := createCertificate("example.com")
	if err != nil {
		t.Fatal(err)
	}
	testKeys.setNitridingKeys(key, cert)
	return testKeys
}

func TestSetKeys(t *testing.T) {
	var (
		keys     enclaveKeys
		appKeys  = []byte("AppKeys")
		testKeys = newTestKeys(t)
	)

	// Ensure that the application keys are set correctly.
	keys = enclaveKeys{}
	keys.setAppKeys(appKeys)
	if !bytes.Equal(keys.AppKeys, appKeys) {
		t.Fatal("Application keys not set correctly.")
	}

	// Ensure that the nitriding keys are set correctly.
	keys = enclaveKeys{}
	keys.setNitridingKeys(testKeys.NitridingKey, testKeys.NitridingCert)
	if !bytes.Equal(keys.NitridingKey, testKeys.NitridingKey) {
		t.Fatal("Nitriding key not set correctly.")
	}
	if !bytes.Equal(keys.NitridingCert, testKeys.NitridingCert) {
		t.Fatal("Nitriding cert not set correctly.")
	}

	// Ensure that a new set of keys is set correctly.
	keys = enclaveKeys{}
	keys.set(testKeys)
	if !keys.equal(testKeys) {
		t.Fatal("Enclave keys not set correctly.")
	}
}

func TestGetKeys(t *testing.T) {
	var (
		testKeys = newTestKeys(t)
		appKeys  = testKeys.getAppKeys()
		keys     = testKeys.get()
	)

	// Ensure that the application key is retrieved correctly.
	if !bytes.Equal(appKeys, testKeys.AppKeys) {
		t.Fatal("Application keys not retrieved correctly.")
	}

	// Ensure that a new set of keys is retrieved correctly.
	if !keys.equal(testKeys) {
		t.Fatal("Enclave keys not retrieved correctly.")
	}
}

func TestModifyCloneObject(t *testing.T) {
	var (
		keys       = newTestKeys(t)
		clonedKeys = keys.get()
	)

	// Make sure that setting the clone's application keys does not affect the
	// original object.
	keys.setAppKeys([]byte("foobar"))
	if bytes.Equal(keys.getAppKeys(), clonedKeys.getAppKeys()) {
		t.Fatal("Cloned object must not affect original object.")
	}
}
