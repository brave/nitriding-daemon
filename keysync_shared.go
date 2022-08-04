package nitriding

import (
	cryptoRand "crypto/rand"
	"encoding/base64"
	"time"

	"golang.org/x/crypto/nacl/box"
)

const (
	boxKeyLen = 32 // NaCl box's private and public key length.
)

var (
	// Instead of using rand.Read or time.Now directly, we use the following
	// variables to enable mocking as part of our unit tets.
	cryptoRead  = cryptoRand.Read
	currentTime = func() time.Time { return time.Now().UTC() }
)

// nonce represents a nonce that's used to prove the freshness of an enclave's
// attestation document.
type nonce [nonceLen]byte

// boxKey represents key material for NaCl's box, i.e., a private and a public
// key.
type boxKey struct {
	pubKey  *[boxKeyLen]byte
	privKey *[boxKeyLen]byte
}

// newBoxKey creates and returns a key pair for use with box.
func newBoxKey() (*boxKey, error) {
	pubKey, privKey, err := box.GenerateKey(cryptoRand.Reader)
	if err != nil {
		return nil, err
	}
	return &boxKey{pubKey: pubKey, privKey: privKey}, nil
}

// newNonce creates and returns a cryptographically secure, random nonce.
func newNonce() (nonce, error) {
	var n nonce
	if _, err := cryptoRead(n[:]); err != nil {
		return nonce{}, err
	}
	return n, nil
}

// B64 returns a Base64-encoded representation of the nonce.
func (n *nonce) B64() string {
	return base64.StdEncoding.EncodeToString(n[:])
}
