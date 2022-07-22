package nitriding

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hf/nitrite"
	"golang.org/x/crypto/nacl/secretbox"
)

// RequestKeys asks a remote enclave to share its key material with us, which
// is then written to the provided variable.
//
// This is only necessary if you intend to scale enclaves using Kubernetes.  If
// you will only ever run a single enclave, ignore this function.
func RequestKeys(addr string, keyMaterial any) error {
	errStr := "failed to request key material"

	// First, request a nonce from the remote enclave.
	theirNonce, err := requestNonce(addr)
	if err != nil {
		return fmt.Errorf("%s: %s", errStr, err)
	}

	// Now, create our own nonce.
	ourNonce, err := newNonce()
	if err != nil {
		return fmt.Errorf("%s: %s", errStr, err)
	}

	// Next, create a key that the remote enclave is going to use to encrypt
	// its key material.
	sbKey, err := newSbKey()
	if err != nil {
		return fmt.Errorf("%s: %s", errStr, err)
	}

	// Now create an attestation document containing our nonce, the remote
	// enclave's nonce, and the key material that they remote enclave is
	// supposed to use.
	ourAttDoc, err := attest(theirNonce[:], ourNonce[:], sbKey.Bytes())
	if err != nil {
		return fmt.Errorf("%s: %s", errStr, err)
	}

	// Send our attestation document to the remote enclave, and get theirs in
	// return.
	theirAttDoc, err := requestAttDoc(addr, ourAttDoc)
	if err != nil {
		return fmt.Errorf("%s: %s", errStr, err)
	}

	// Finally, verify the attestation document and extract the key material.
	if err := processAttDoc(theirAttDoc, &ourNonce, sbKey, keyMaterial); err != nil {
		return fmt.Errorf("%s: %s", errStr, err)
	}

	return nil
}

// requestNonce requests a nonce from the remote enclave specified by 'addr'.
func requestNonce(addr string) (nonce, error) {
	errStr := "failed to fetch nonce from remote enclave"

	endpoint := fmt.Sprintf("%s%s", addr, pathNonce)
	resp, err := http.Get(endpoint)
	if err != nil {
		return nonce{}, fmt.Errorf("%s: %s", errStr, err)
	}
	defer resp.Body.Close()

	bufSize := base64.StdEncoding.EncodedLen(nonceLen)
	bodyBuf := make([]byte, bufSize)
	if _, err := io.ReadFull(resp.Body, bodyBuf); err != nil {
		return nonce{}, fmt.Errorf("%s: %s", errStr, err)
	}

	// Decode the Base64-encoded nonce.
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(bodyBuf)))
	if err != nil {
		return nonce{}, fmt.Errorf("%s: %s", errStr, err)
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
		"application/octet-stream",
		bytes.NewBufferString(b64AttDoc),
	)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", errStr, err)
	}
	defer resp.Body.Close()

	bufSize := base64.StdEncoding.EncodedLen(maxAttDocLen)
	bodyBuf := make([]byte, bufSize)
	if _, err := io.ReadFull(resp.Body, bodyBuf); err != nil {
		return nil, fmt.Errorf("%s: %s", errStr, err)
	}

	theirAttDoc, err := base64.StdEncoding.DecodeString(string(bodyBuf))
	if err != nil {
		return nil, fmt.Errorf("%s: %s", errStr, err)
	}

	return theirAttDoc, nil
}

// processAttDoc first verifies that the remote enclave's attestation document
// is authentic, and then attempts to decrypt and extract the key material that
// the remote enclave provided in its attestation document.
func processAttDoc(
	theirAttDoc []byte,
	ourNonce *nonce,
	sbKey *sbKey,
	keyMaterial any,
) error {
	errStr := "failed to process attestation doc from remote enclave"
	// Verify the remote enclave's attestation document before doing anything
	// with it.
	opts := nitrite.VerifyOptions{CurrentTime: time.Now().UTC()}
	res, err := nitrite.Verify(theirAttDoc, opts)
	if err != nil {
		return fmt.Errorf("%s: %s", errStr, err)
	}

	// Now verify that the remote enclave's attestation document contains the
	// nonce that we provided earlier.
	if !bytes.Equal(res.Document.Nonce, ourNonce[:]) {
		return fmt.Errorf("%s: expected nonce %x but got %x",
			errStr, ourNonce[:], res.Document.Nonce)
	}

	// Attempt to decrypt the key material.
	var decrypted []byte
	_, ok := secretbox.Open(decrypted, res.Document.PublicKey, &sbKey.nonce, &sbKey.key)
	if !ok {
		return fmt.Errorf("%s: failed to decrypt key material", errStr)
	}

	// Finally, write the JSON-encoded key material to the provided interface.
	if err := json.Unmarshal(decrypted, keyMaterial); err != nil {
		return fmt.Errorf("%s: %s", errStr, err)
	}

	return nil
}
