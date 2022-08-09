package nitriding

// AWS Nitro Enclave attestation documents contain three fields (called
// "nonce", "user data",  and "public key") that can be set by the requester.
// We are using those fields as follows:
//
// When the requesting enclave sends a request to the remote enclave, it sets
// the following fields in the attestation document:
//
// Attestation document(
//   Nonce:       Remote enclave's nonce
//   User data:   Requesting enclave's nonce
//   Public key:  Requesting enclave's NaCl box public key
// )
//
// The remote enclave then generates its own attestation document containing
// the following fields:
//
// Attestation document(
//   Nonce:       The nonce the requester provided in its attestation document
//   User data:   Encrypted key material
//   Public key:
// )

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hf/nitrite"
	"golang.org/x/crypto/nacl/box"
)

// RequestKeys asks a remote enclave to share its key material with us, which
// is then written to the provided variable.
//
// This is only necessary if you intend to scale enclaves horizontally.  If
// you will only ever run a single enclave, ignore this function.
func RequestKeys(addr string, keyMaterial any) error {
	errStr := "failed to request key material"

	// First, request a nonce from the remote enclave.
	theirNonce, err := requestNonce(addr)
	if err != nil {
		return fmt.Errorf("%s: %w", errStr, err)
	}

	// Now, create our own nonce.
	ourNonce, err := newNonce()
	if err != nil {
		return fmt.Errorf("%s: %w", errStr, err)
	}

	// Next, create a key that the remote enclave is going to use to encrypt
	// its key material.
	boxKey, err := newBoxKey()
	if err != nil {
		return fmt.Errorf("%s: %w", errStr, err)
	}

	// Now create an attestation document containing our nonce, the remote
	// enclave's nonce, and the key material that they remote enclave is
	// supposed to use.
	ourAttDoc, err := attest(theirNonce[:], ourNonce[:], boxKey.pubKey[:])
	if err != nil {
		return fmt.Errorf("%s: %w", errStr, err)
	}

	// Send our attestation document to the remote enclave, and get theirs in
	// return.
	theirAttDoc, err := requestAttDoc(addr, ourAttDoc)
	if err != nil {
		return fmt.Errorf("%s: %w", errStr, err)
	}

	// Finally, verify the attestation document and extract the key material.
	if err := processAttDoc(theirAttDoc, &ourNonce, boxKey, keyMaterial); err != nil {
		return fmt.Errorf("%s: %w", errStr, err)
	}

	return nil
}

// requestNonce requests a nonce from the remote enclave specified by 'addr'.
func requestNonce(addr string) (nonce, error) {
	errStr := "failed to fetch nonce from remote enclave"

	endpoint := fmt.Sprintf("%s%s", addr, pathNonce)
	resp, err := http.Get(endpoint)
	if err != nil {
		return nonce{}, fmt.Errorf("%s: %w", errStr, err)
	}
	defer resp.Body.Close()

	maxReadLen := base64.StdEncoding.EncodedLen(nonceLen)
	body, err := io.ReadAll(newLimitReader(resp.Body, maxReadLen))
	if err != nil {
		return nonce{}, fmt.Errorf("%s: %w", errStr, err)
	}

	// Decode the Base64-encoded nonce.
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		return nonce{}, fmt.Errorf("%s: %w", errStr, err)
	}

	if len(raw) != nonceLen {
		return nonce{}, errors.New("remote enclave's nonce has incorrect length")
	}
	var n nonce
	copy(n[:], raw)
	return n, nil
}

// requestAttDoc takes as input the remote enclave's address (e.g.,
// <https://example.com>) and our attestation document.  The function then
// submits our attestation document to the remote enclave, and returns the
// remote enclave's attestation document.
func requestAttDoc(addr string, ourAttDoc []byte) ([]byte, error) {
	errStr := "failed to fetch attestation doc from remote enclave"

	endpoint := fmt.Sprintf("%s%s", addr, pathKeys)

	// Finally, send our attestation document to the remote enclave.  If
	// everything works out, the remote enclave is going to respond with its
	// attestation document.
	b64AttDoc := base64.StdEncoding.EncodeToString(ourAttDoc)
	resp, err := http.Post(
		endpoint,
		"text/plain",
		bytes.NewBufferString(b64AttDoc),
	)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errStr, err)
	}
	defer resp.Body.Close()

	maxReadLen := base64.StdEncoding.EncodedLen(maxAttDocLen)
	body, err := io.ReadAll(newLimitReader(resp.Body, maxReadLen))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errStr, err)
	}

	theirAttDoc, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errStr, err)
	}

	return theirAttDoc, nil
}

// processAttDoc first verifies that the remote enclave's attestation document
// is authentic, and then attempts to decrypt and extract the key material that
// the remote enclave provided in its attestation document.
func processAttDoc(
	theirAttDoc []byte,
	ourNonce *nonce,
	boxKey *boxKey,
	keyMaterial any,
) error {
	errStr := "failed to process attestation doc from remote enclave"
	// Verify the remote enclave's attestation document before doing anything
	// with it.
	opts := nitrite.VerifyOptions{CurrentTime: currentTime()}
	their, err := nitrite.Verify(theirAttDoc, opts)
	if err != nil {
		return fmt.Errorf("%s: %w", errStr, err)
	}

	// Are the PCR values (i.e. image IDs) identical?
	ourPCRs, err := getPCRValues()
	if err != nil {
		return fmt.Errorf("%s: %w", errStr, err)
	}
	if !arePCRsIdentical(ourPCRs, their.Document.PCRs) {
		return fmt.Errorf("%s: PCR values of remote enclave not identical to ours", errStr)
	}

	// Now verify that the remote enclave's attestation document contains the
	// nonce that we provided earlier.
	if !bytes.Equal(their.Document.Nonce, ourNonce[:]) {
		return fmt.Errorf("%s: expected nonce %x but got %x",
			errStr, ourNonce[:], their.Document.Nonce)
	}

	// Attempt to decrypt the key material.
	decrypted, ok := box.OpenAnonymous(
		nil,
		their.Document.UserData,
		boxKey.pubKey,
		boxKey.privKey)
	if !ok {
		return fmt.Errorf("%s: failed to decrypt key material", errStr)
	}

	// Finally, write the JSON-encoded key material to the provided interface.
	if err := json.Unmarshal(decrypted, keyMaterial); err != nil {
		return fmt.Errorf("%s: %w", errStr, err)
	}

	return nil
}
