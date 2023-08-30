package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hf/nitrite"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

// attester defines functions for the creation and verification of attestation
// documents.  Making this an interface helps with testing: It allows us to
// implement a dummy attester that works without the AWS Nitro hypervisor.
type attester interface {
	createAttstn(auxInfo) ([]byte, error)
	verifyAttstn([]byte, nonce) (auxInfo, error)
}

type auxInfo interface{}

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

func (w workerAuxInfo) String() string {
	return fmt.Sprintf("Worker's auxiliary info:\n"+
		"Worker's nonce: %x\nLeader's nonce: %x\nPublic key: %x",
		w.WorkersNonce, w.LeadersNonce, w.PublicKey)
}

// leaderAuxInfo holds the auxiliary information of the leader's attestation
// document.
type leaderAuxInfo struct {
	WorkersNonce nonce  `json:"workers_nonce"`
	EnclaveKeys  []byte `json:"enclave_keys"`
}

func (l leaderAuxInfo) String() string {
	return fmt.Sprintf("Leader's auxiliary info:\n"+
		"Worker's nonce: %x\nEnclave keys: %x",
		l.WorkersNonce, l.EnclaveKeys)
}

// dummyAttester helps with local testing.  The interface simply turns
// auxiliary information into JSON, and does not do any cryptography.
type dummyAttester struct{}

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
	if len(w.WorkersNonce) == nonceLen && len(w.LeadersNonce) == nonceLen && w.PublicKey != nil {
		if n.B64() != w.LeadersNonce.B64() {
			return nil, errors.New("leader nonce not in cache")
		}
		return &w, nil
	}

	// Next, let's assume it's a leader.
	if err := json.Unmarshal(doc, &l); err != nil {
		return nil, err
	}
	if len(l.WorkersNonce) == nonceLen && l.EnclaveKeys != nil {
		if n.B64() != l.WorkersNonce.B64() {
			return nil, errors.New("worker nonce not in cache")
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
	return &nitroAttester{}
}

// createAttstn asks the AWS Nitro Enclave hypervisor for an attestation
// document that contains the given auxiliary information.
func (*nitroAttester) createAttstn(aux auxInfo) ([]byte, error) {
	var nonce, userData, publicKey []byte

	// Prepare our auxiliary information.
	switch v := aux.(type) {
	case workerAuxInfo:
		nonce = v.WorkersNonce[:]
		userData = v.LeadersNonce[:]
		publicKey = v.PublicKey
	case leaderAuxInfo:
		nonce = v.WorkersNonce[:]
		userData = v.EnclaveKeys
	case clientAuxInfo:
		nonce = v.clientNonce[:]
		userData = v.attestationHashes
	}

	s, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err = s.Close(); err != nil {
			elog.Printf("Error closing NSM session: %v", err)
		}
	}()

	res, err := s.Send(&request.Attestation{
		Nonce:     nonce,
		UserData:  userData,
		PublicKey: publicKey,
	})
	if err != nil {
		return nil, err
	}
	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, errors.New("NSM device did not return an attestation")
	}

	return res.Attestation.Document, nil
}

// verifyAttstn verifies the given attestation document and, if successful,
// returns the document's auxiliary information.
func (*nitroAttester) verifyAttstn(doc []byte, n nonce) (auxInfo, error) {
	errStr := "error verifying attestation document"
	// Verify the remote enclave's attestation document before doing anything
	// with it.
	opts := nitrite.VerifyOptions{CurrentTime: currentTime()}
	their, err := nitrite.Verify(doc, opts)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", errStr, err)
	}

	// Verify that the remote enclave's PCR values (e.g., the image ID) are
	// identical to ours.
	ourPCRs, err := getPCRValues()
	if err != nil {
		return nil, fmt.Errorf("%v: %w", errStr, err)
	}
	if !arePCRsIdentical(ourPCRs, their.Document.PCRs) {
		elog.Printf("Our PCR values:\n%s", prettyFormat(ourPCRs))
		elog.Printf("Their PCR values:\n%s", prettyFormat(their.Document.PCRs))
		return nil, fmt.Errorf("%v: PCR values of remote enclave not identical to ours", errStr)
	}

	// Verify that the remote enclave's attestation document contains the nonce
	// that we asked it to embed.
	b64Nonce := base64.StdEncoding.EncodeToString(their.Document.Nonce)
	if n.B64() == b64Nonce {
		return nil, fmt.Errorf("%v: nonce %s not in cache", errStr, b64Nonce)
	}

	workersNonce, err := sliceToNonce(their.Document.Nonce)
	if err != nil {
		return nil, err
	}
	leadersNonce, err := sliceToNonce(their.Document.UserData)
	if err != nil {
		return nil, err
	}
	// If the "public key" field is unset, we know that we're dealing with a
	// worker's auxiliary information.
	if their.Document.PublicKey != nil {
		return &workerAuxInfo{
			WorkersNonce: workersNonce,
			LeadersNonce: leadersNonce,
			PublicKey:    their.Document.PublicKey,
		}, nil
	}

	workersNonce, err = sliceToNonce(their.Document.Nonce)
	if err != nil {
		return nil, err
	}
	return &leaderAuxInfo{
		WorkersNonce: workersNonce,
		EnclaveKeys:  their.Document.UserData,
	}, nil
}
