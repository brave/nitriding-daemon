package nitriding

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/hf/nitrite"
	"golang.org/x/crypto/nacl/secretbox"
)

var (
	errFailedNonce     = "failed to create nonce"
	errNoBase64        = "failed to Base64-decode attestation document"
	errFailedVerify    = "failed to verify attestation document"
	errFailedFindNonce = "could not find provided nonce"
	errInvalidSbKeys   = "invalid secretbox key material"
)

type timeFunc func() time.Time

// getNonceHandler returns a HandlerFunc that creates a new nonce and returns
// it to the client.
func getNonceHandler(e *Enclave) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nonce, err := newNonce()
		if err != nil {
			http.Error(w, errFailedNonce, http.StatusInternalServerError)
			return
		}

		e.nonceCache.Add(nonce.B64())
		fmt.Fprintf(w, "%s\n", nonce.B64())
	}
}

func getKeysHandler(e *Enclave, curTime timeFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var ourNonce, theirNonce nonce

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusInternalServerError)
			return
		}
		theirRawAttDoc, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
		if err != nil {
			http.Error(w, errNoBase64, http.StatusInternalServerError)
			return
		}

		// Verify the remote enclave's attestation document before touching it.
		opts := nitrite.VerifyOptions{CurrentTime: curTime().UTC()}
		res, err := nitrite.Verify(theirRawAttDoc, opts)
		if err != nil {
			http.Error(w, errFailedVerify, http.StatusUnauthorized)
			return
		}
		theirAttDoc := res.Document

		// Did we actually issue the nonce that the remote enclave provided?
		copy(ourNonce[:], theirAttDoc.Nonce)
		if !e.nonceCache.Exists(ourNonce.B64()) {
			fmt.Printf("could not find nonce %s\n", ourNonce.B64())
			http.Error(w, "could not find provided nonce", http.StatusUnauthorized)
			return
		}

		// If we made it this far, we're convinced that we're talking to an
		// identical enclave.  Now get the remote enclave's nonce, which is in
		// the attestation document's "user data" field.
		copy(theirNonce[:], theirAttDoc.UserData)

		sbKey, err := newSbKeyFromBytes(theirAttDoc.PublicKey)
		if err != nil {
			http.Error(w, errInvalidSbKeys, http.StatusBadRequest)
			return
		}

		// Encrypt our key material with the provided key.
		jsonKeyMaterial, err := json.Marshal(e.keyMaterial)
		if err != nil {
			http.Error(w, "failed to marshal key material", http.StatusInternalServerError)
			return
		}
		var encrypted []byte
		secretbox.Seal(encrypted, jsonKeyMaterial, &sbKey.nonce, &sbKey.key)

		// Encapsulate the remote enclave's nonce and the encrypted key
		// material in an attestation document and send it back.
		ourAttDoc, err := attest(theirNonce[:], nil, encrypted)
		if err != nil {
			http.Error(w, errFailedAttestation, http.StatusInternalServerError)
			return
		}

		b64AttDoc := base64.StdEncoding.EncodeToString(ourAttDoc)
		fmt.Fprint(w, b64AttDoc)
	}
}
