package nitriding

import (
	cryptoRand "crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/nacl/box"
)

const (
	boxKeyLen   = 32 // NaCl box's private and public key length.
	boxNonceLen = 24 // NaCl box's nonce length.
)

var (
	// Instead of using rand.Read directly, we use this variable to facilitate
	// testing.
	cryptoRead = cryptoRand.Read
)

// nonce represents a nonce that's used to prove the freshness of an enclave's
// attestation document.
type nonce [nonceLen]byte

// boxKey represents key material for NaCl's box, i.e., a nonce and a key
// pair.
type boxKey struct {
	nonce   *[boxNonceLen]byte
	pubKey  *[boxKeyLen]byte
	privKey *[boxKeyLen]byte
}

// newBoxKey creates and returns key material (i.e., a key pair and a nonce)
// for use with box.
func newBoxKey() (*boxKey, error) {
	var err error
	k := &boxKey{
		nonce: &[boxNonceLen]byte{},
	}

	k.pubKey, k.privKey, err = box.GenerateKey(cryptoRand.Reader)
	if err != nil {
		return nil, err
	}

	if _, err = cryptoRead(k.nonce[:]); err != nil {
		return nil, err
	}

	return k, nil
}

// newBoxKeyFromBytes returns the boxKey struct that's represented by the
// given byte slice.
func newBoxKeyFromBytes(b []byte) (*boxKey, error) {
	if len(b) != (boxNonceLen + boxKeyLen) {
		return nil, errors.New("incorrect length of given box key material")
	}

	k := &boxKey{
		nonce:   &[boxNonceLen]byte{},
		pubKey:  &[boxKeyLen]byte{},
		privKey: &[boxKeyLen]byte{},
	}
	copy(k.nonce[:], b[:boxNonceLen])
	copy(k.pubKey[:], b[boxNonceLen:])
	return k, nil
}

// Bytes returns the public key material in the form of a byte slice.
func (k *boxKey) Bytes() []byte {
	return append(k.nonce[:], k.pubKey[:]...)
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
