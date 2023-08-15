package main

import (
	cryptoRand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

// leaderSync holds the state and code that we need for a one-off sync with a
// worker enclave.
type leaderSync struct {
	attester
	keys *enclaveKeys
}

// asLeader returns a new leaderSync struct.
func asLeader(keys *enclaveKeys) *leaderSync {
	return &leaderSync{
		attester: &dummyAttester{},
		keys:     keys,
	}
}

// syncWith makes the leader initiate key synchronization with the given worker
// enclave.
func (s *leaderSync) syncWith(worker *url.URL) error {
	elog.Println("Initiating key synchronization with worker.")

	// Step 1: Create a nonce that the worker must embed in its attestation
	// document, to prevent replay attacks.
	nonce, err := newNonce()
	if err != nil {
		return err
	}

	// Step 2: Request the worker's attestation document, and provide the
	// previously-generated nonce.
	reqURL := *worker
	reqURL.RawQuery = fmt.Sprintf("nonce=%x", nonce)
	resp, err := newUnauthenticatedHTTPClient().Get(reqURL.String())
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errNo200(resp.StatusCode)
	}

	// Step 3: Verify the worker's attestation document and extract its
	// auxiliary information.
	b64Attstn, err := io.ReadAll(newLimitReader(resp.Body, maxAttDocLen))
	if err != nil {
		return err
	}
	resp.Body.Close()
	attstn, err := base64.StdEncoding.DecodeString(string(b64Attstn))
	if err != nil {
		return err
	}
	workerAux, err := s.verifyAttstn(attstn, nonce)
	if err != nil {
		return err
	}

	// Step 4: Encrypt the leader's enclave keys with the ephemeral public key
	// that the worker put into its auxiliary information.
	pubKey := &[boxKeyLen]byte{}
	copy(pubKey[:], workerAux.(*workerAuxInfo).PublicKey[:])
	jsonKeys, err := json.Marshal(s.keys.get())
	if err != nil {
		return err
	}
	var encrypted []byte
	encrypted, err = box.SealAnonymous(nil, jsonKeys, pubKey, cryptoRand.Reader)
	if err != nil {
		return err
	}

	// Step 5: Create the leader's auxiliary information, consisting of the
	// worker's nonce and the encrypted enclave keys.
	leaderAux := &leaderAuxInfo{
		WorkersNonce: workerAux.(*workerAuxInfo).WorkersNonce,
		EnclaveKeys:  encrypted,
	}
	attstn, err = s.createAttstn(leaderAux)
	if err != nil {
		return err
	}
	strAttstn := base64.StdEncoding.EncodeToString(attstn)

	// Step 6: Send the leader's attestation document to the worker.
	resp, err = newUnauthenticatedHTTPClient().Post(worker.String(), "text/plain", strings.NewReader(strAttstn))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errNo200(resp.StatusCode)
	}

	return nil
}
