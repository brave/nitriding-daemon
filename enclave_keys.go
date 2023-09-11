package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"sync"
)

// enclaveKeys holds key material for nitriding itself (the HTTPS certificate)
// and for the enclave application (whatever the application wants to "store"
// in nitriding).  These keys are meant to be managed by a leader enclave and --
// if horizontal scaling is required -- synced to worker enclaves.  The struct
// implements getters and setters that allow for thread-safe setting and getting
// of members.
type enclaveKeys struct {
	sync.Mutex
	NitridingKey  []byte `json:"nitriding_key"`
	NitridingCert []byte `json:"nitriding_cert"`
	AppKeys       []byte `json:"app_keys"`
}

func (e1 *enclaveKeys) equal(e2 *enclaveKeys) bool {
	e1.Lock()
	e2.Lock()
	defer e1.Unlock()
	defer e2.Unlock()

	return bytes.Equal(e1.NitridingCert, e2.NitridingCert) &&
		bytes.Equal(e1.NitridingKey, e2.NitridingKey) &&
		bytes.Equal(e1.AppKeys, e2.AppKeys)
}

func (e *enclaveKeys) setAppKeys(appKeys []byte) {
	e.Lock()
	defer e.Unlock()

	e.AppKeys = appKeys
}

func (e *enclaveKeys) setNitridingKeys(key, cert []byte) {
	e.Lock()
	defer e.Unlock()

	e.NitridingKey = key
	e.NitridingCert = cert
}

func (e *enclaveKeys) set(newKeys *enclaveKeys) {
	e.setAppKeys(newKeys.AppKeys)
	e.setNitridingKeys(newKeys.NitridingKey, newKeys.NitridingCert)
}

func (e *enclaveKeys) copy() *enclaveKeys {
	e.Lock()
	defer e.Unlock()

	return &enclaveKeys{
		NitridingKey:  e.NitridingKey,
		NitridingCert: e.NitridingCert,
		AppKeys:       e.AppKeys,
	}
}

func (e *enclaveKeys) getAppKeys() []byte {
	e.Lock()
	defer e.Unlock()

	return e.AppKeys
}

// hashAndB64 returns the Base64-encoded hash over our key material.  The
// resulting string is not confidential as it's impractical to reverse the key
// material.
func (e *enclaveKeys) hashAndB64() string {
	e.Lock()
	defer e.Unlock()

	keys := append(append(e.NitridingCert, e.NitridingKey...), e.AppKeys...)
	hash := sha256.Sum256(keys)
	return base64.StdEncoding.EncodeToString(hash[:])
}
