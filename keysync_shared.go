package nitriding

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

const (
	sbKeyLen   = 32 // secretbox's key length.
	sbNonceLen = 24 // secretbox's nonce length.
)

var (
	// Instead of using rand.Read directly, we use this variable to facilitate
	// testing.
	cryptoRead = rand.Read
)

// nonce represents a nonce that's used to prove the freshness of an enclave's
// attestation document.
type nonce [nonceLen]byte

// sbKeyLen represents key material for secretbox, i.e., a nonce and a key.
type sbKey struct {
	nonce [sbNonceLen]byte
	key   [sbKeyLen]byte
}

// newSbKey creates and returns key material (i.e., a secret key and a nonce)
// for use with secretbox.
func newSbKey() (*sbKey, error) {
	k := &sbKey{}

	if _, err := cryptoRead(k.key[:]); err != nil {
		return nil, err
	}
	if _, err := cryptoRead(k.nonce[:]); err != nil {
		return nil, err
	}

	return k, nil
}

// newSbKeyFromBytes returns the sbKey struct that's represented by the given
// byte slice.
func newSbKeyFromBytes(b []byte) (*sbKey, error) {
	if len(b) != (sbNonceLen + sbKeyLen) {
		return nil, errors.New("incorrect length of given secretbox key material")
	}

	k := &sbKey{}
	copy(k.nonce[:], b[:sbNonceLen])
	copy(k.key[:], b[sbNonceLen:])
	return k, nil
}

// Bytes returns the key material in the form of a byte slice.
func (k *sbKey) Bytes() []byte {
	return append(k.nonce[:], k.key[:]...)
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
