package nitriding

import (
	cryptoRand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hf/nitrite"
	"golang.org/x/crypto/nacl/box"
)

var (
	errFailedNonce     = errors.New("failed to create nonce")
	errNoBase64        = errors.New("failed to Base64-decode attestation document")
	errFailedVerify    = errors.New("failed to verify attestation document")
	errFailedRespBody  = errors.New("failed to read response body")
	errFailedPCR       = errors.New("failed to get PCR values")
	errFailedFindNonce = errors.New("could not find provided nonce")
	errInvalidBoxKeys  = errors.New("invalid box key material")
	errPCRNotIdentical = errors.New("remote enclave's PCR values not identical")
)

type timeFunc func() time.Time

// getNonceHandler returns a HandlerFunc that creates a new nonce and returns
// it to the client.
func getNonceHandler(e *Enclave) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nonce, err := newNonce()
		if err != nil {
			http.Error(w, errFailedNonce.Error(), http.StatusInternalServerError)
			return
		}

		e.nonceCache.Add(nonce.B64())
		fmt.Fprintf(w, "%s\n", nonce.B64())
	}
}

// getKeysHandler returns a HandlerFunc that shares our secret key material
// with the requesting enclave -- after authentication, of course.
func getKeysHandler(e *Enclave, curTime timeFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var ourNonce, theirNonce nonce

		maxReadLen := base64.StdEncoding.EncodedLen(maxAttDocLen)
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(maxReadLen)))
		if err != nil {
			http.Error(w, errFailedRespBody.Error(), http.StatusInternalServerError)
			return
		}
		theirRawAttDoc, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
		if err != nil {
			http.Error(w, errNoBase64.Error(), http.StatusInternalServerError)
			return
		}

		// Verify the remote enclave's attestation document before touching it.
		opts := nitrite.VerifyOptions{CurrentTime: currentTime()}
		res, err := nitrite.Verify(theirRawAttDoc, opts)
		if err != nil {
			http.Error(w, errFailedVerify.Error(), http.StatusUnauthorized)
			return
		}
		theirAttDoc := res.Document

		// Are the PCR values (i.e. image IDs) identical?
		ourPCRs, err := getPCRValues()
		if err != nil {
			http.Error(w, errFailedPCR.Error(), http.StatusInternalServerError)
			return
		}
		if !arePCRsIdentical(ourPCRs, theirAttDoc.PCRs) {
			http.Error(w, errPCRNotIdentical.Error(), http.StatusUnauthorized)
			return
		}

		// Did we actually issue the nonce that the remote enclave provided?
		copy(ourNonce[:], theirAttDoc.Nonce)
		if !e.nonceCache.Exists(ourNonce.B64()) {
			http.Error(w, errFailedFindNonce.Error(), http.StatusUnauthorized)
			return
		}

		// If we made it this far, we're convinced that we're talking to an
		// identical enclave.  Now get the remote enclave's nonce, which is in
		// the attestation document's "user data" field.
		copy(theirNonce[:], theirAttDoc.UserData)

		if len(theirAttDoc.PublicKey) != boxKeyLen {
			http.Error(w, errInvalidBoxKeys.Error(), http.StatusBadRequest)
			return
		}
		theirBoxPubKey := &[boxKeyLen]byte{}
		copy(theirBoxPubKey[:], theirAttDoc.PublicKey[:])

		// Encrypt our key material with the provided key.
		jsonKeyMaterial, err := json.Marshal(e.keyMaterial)
		if err != nil {
			http.Error(w, "failed to marshal key material", http.StatusInternalServerError)
			return
		}
		var encrypted []byte
		if _, err = box.SealAnonymous(
			encrypted,
			jsonKeyMaterial,
			theirBoxPubKey,
			cryptoRand.Reader,
		); err != nil {
			http.Error(w, "failed to encrypt key material", http.StatusInternalServerError)
			return
		}

		// Encapsulate the remote enclave's nonce and the encrypted key
		// material in an attestation document and send it back.
		ourAttDoc, err := attest(theirNonce[:], encrypted, nil)
		if err != nil {
			http.Error(w, errFailedAttestation, http.StatusInternalServerError)
			return
		}

		b64AttDoc := base64.StdEncoding.EncodeToString(ourAttDoc)
		fmt.Fprint(w, b64AttDoc)
	}
}
