package main

import (
	cryptoRand "crypto/rand"
	"time"

	"golang.org/x/crypto/nacl/box"
)

const (
	maxAttstnBodyLen = 256 * 1024 // Upper limit for attestation body length.
	boxKeyLen        = 32         // NaCl box's private and public key length.
)

var (
	// Instead of using rand.Read or time.Now directly, we use the following
	// variables to enable mocking as part of our unit tets.
	cryptoRead  = cryptoRand.Read
	currentTime = func() time.Time { return time.Now().UTC() }
)

// attstnBody contains a JSON-formatted, Base64-encoded attestation document and
// encrypted key material.  The leader and worker use this struct to exchange
// attestation documents.
type attstnBody struct {
	Document      string `json:"document"`
	EncryptedKeys string `json:"encrypted_keys"`
}

// boxKey represents key material for NaCl's box, i.e., a private and a public
// key.
type boxKey struct {
	pubKey  *[boxKeyLen]byte
	privKey *[boxKeyLen]byte
}

// newBoxKey returns a key pair for use with box.
func newBoxKey() (*boxKey, error) {
	pubKey, privKey, err := box.GenerateKey(cryptoRand.Reader)
	if err != nil {
		return nil, err
	}
	return &boxKey{
		pubKey:  pubKey,
		privKey: privKey,
	}, nil
}
