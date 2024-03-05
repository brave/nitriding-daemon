package main

import (
	"encoding/base64"
	"errors"
)

const nonceLen = 20 // The size of a nonce in bytes.

var errNotEnoughRead = errors.New("failed to read enough random bytes")

// nonce represents a nonce that's used to prove the freshness of an enclave's
// attestation document.
type nonce [nonceLen]byte

// newNonce returns a cryptographically secure, random nonce.
func newNonce() (nonce, error) {
	var newNonce nonce
	n, err := cryptoRead(newNonce[:])
	if err != nil {
		return nonce{}, err
	}
	if n != nonceLen {
		return nonce{}, errNotEnoughRead
	}
	return newNonce, nil
}

// b64 returns a Base64-encoded representation of the nonce.
func (n *nonce) b64() string {
	return base64.StdEncoding.EncodeToString(n[:])
}
