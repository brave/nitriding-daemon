package main

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/hf/nitrite"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

var (
	errPCRMismatch     = errors.New("PCR values differ")
	errNonceMismatch   = errors.New("nonce is unexpected")
	errNoAttstnFromNSM = errors.New("NSM device did not return an attestation")
	padding            = []byte("dummy")
)

// attester defines functions for the creation and verification of attestation
// documents.  Making this an interface helps with testing: It allows us to
// implement a dummy attester that works without the AWS Nitro hypervisor.
type attester interface {
	createAttstn(auxInfo) ([]byte, error)
	verifyAttstn([]byte, nonce) (auxInfo, error)
}

type auxInfo interface{}

// workerAuxInfo holds the auxilitary information of an attestation document
// requested by clients.
type clientAuxInfo struct {
	clientNonce       nonce
	attestationHashes []byte
}

// workerAuxInfo holds the auxiliary information of the worker's attestation
// document.
type workerAuxInfo struct {
	WorkersNonce nonce  `json:"workers_nonce"`
	LeadersNonce nonce  `json:"leaders_nonce"`
	PublicKey    []byte `json:"public_key"`
}

// leaderAuxInfo holds the auxiliary information of the leader's attestation
// document.
type leaderAuxInfo struct {
	WorkersNonce    nonce  `json:"workers_nonce"`
	HashOfEncrypted []byte `json:"hash_of_encrypted"`
}

// dummyAttester helps with local testing.  The interface simply turns
// auxiliary information into JSON, and does not do any cryptography.
type dummyAttester struct{}

// newDummyAttester returns a new dummyAttester.
func newDummyAttester() *dummyAttester {
	return new(dummyAttester)
}

func (*dummyAttester) createAttstn(aux auxInfo) ([]byte, error) {
	return json.Marshal(aux)
}

func (*dummyAttester) verifyAttstn(doc []byte, n nonce) (auxInfo, error) {
	var (
		w workerAuxInfo
		l leaderAuxInfo
	)

	// First, assume we're dealing with a worker's auxiliary information.
	if err := json.Unmarshal(doc, &w); err != nil {
		return nil, err
	}
	if w.PublicKey != nil {
		if n.b64() != w.LeadersNonce.b64() {
			return nil, errNonceMismatch
		}
		return &w, nil
	}

	// Next, let's assume it's a leader.
	if err := json.Unmarshal(doc, &l); err != nil {
		return nil, err
	}
	if l.HashOfEncrypted != nil {
		if n.b64() != l.WorkersNonce.b64() {
			return nil, errNonceMismatch
		}
		return &l, nil
	}

	return nil, errors.New("invalid auxiliary information")
}

// nitroAttester implements the attester interface by drawing on the AWS Nitro
// Enclave hypervisor.
type nitroAttester struct{}

// newNitroAttester returns a new nitroAttester.
func newNitroAttester() *nitroAttester {
	return new(nitroAttester)
}

// createAttstn asks the AWS Nitro Enclave hypervisor for an attestation
// document that contains the given auxiliary information.
func (*nitroAttester) createAttstn(aux auxInfo) ([]byte, error) {
	var nonce, userData, publicKey []byte

	// Prepare our auxiliary information.  If the public key field is unused, we
	// pad it with dummy bytes because the nitrite package (which we use to
	// verify attestation documents) expects all three fields to be set.
	switch v := aux.(type) {
	case *workerAuxInfo:
		nonce = v.LeadersNonce[:]
		userData = v.WorkersNonce[:]
		publicKey = v.PublicKey
	case *leaderAuxInfo:
		nonce = v.WorkersNonce[:]
		userData = v.HashOfEncrypted
		publicKey = padding
	case *clientAuxInfo:
		nonce = v.clientNonce[:]
		userData = v.attestationHashes
		publicKey = padding
	}

	s, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, err
	}
	defer s.Close()

	res, err := s.Send(&request.Attestation{
		Nonce:     nonce,
		UserData:  userData,
		PublicKey: publicKey,
	})
	if err != nil {
		return nil, err
	}
	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, errNoAttstnFromNSM
	}

	return res.Attestation.Document, nil
}

// verifyAttstn verifies the given attestation document and, if successful,
// returns the document's auxiliary information.
func (*nitroAttester) verifyAttstn(doc []byte, ourNonce nonce) (auxInfo, error) {
	// First, verify the remote enclave's attestation document.
	opts := nitrite.VerifyOptions{CurrentTime: currentTime()}
	their, err := nitrite.Verify(doc, opts)
	if err != nil {
		return nil, err
	}

	// Verify that the remote enclave's PCR values (e.g., the image ID) are
	// identical to ours.
	ourPCRs, err := getPCRValues()
	if err != nil {
		return nil, err
	}
	if !arePCRsIdentical(ourPCRs, their.Document.PCRs) {
		return nil, errPCRMismatch
	}

	// Verify that the remote enclave's attestation document contains the nonce
	// that we asked it to embed.
	theirNonce, err := sliceToNonce(their.Document.Nonce)
	if err != nil {
		return nil, err
	}
	if ourNonce != theirNonce {
		return nil, errNonceMismatch
	}

	// If the "public key" field contains padding, we know that we're
	// dealing with a leader's auxiliary information.
	if bytes.Equal(their.Document.PublicKey, padding) {
		return &leaderAuxInfo{
			WorkersNonce:    theirNonce,
			HashOfEncrypted: their.Document.UserData,
		}, nil
	}

	workersNonce, err := sliceToNonce(their.Document.UserData)
	if err != nil {
		return nil, err
	}
	return &workerAuxInfo{
		WorkersNonce: workersNonce,
		LeadersNonce: theirNonce,
		PublicKey:    their.Document.PublicKey,
	}, nil
}
