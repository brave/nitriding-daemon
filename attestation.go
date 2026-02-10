package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/hf/nitrite"
)

const (
	nonceNumDigits = nonceLen * 2 // The number of hex digits in a nonce.
)

var (
	errBadForm           = errors.New("failed to parse POST form data")
	errNoNonce           = errors.New("could not find nonce in URL query parameters")
	errBadNonceFormat    = fmt.Errorf("unexpected nonce format; must be %d-digit hex string", nonceNumDigits)
	errFailedAttestation = errors.New("failed to obtain attestation document from hypervisor")
	errProfilingSet      = errors.New("attestation disabled because profiling is enabled")

	// Multihash prefix marks the hash type and digest size
	hashPrefix = []byte{0x12, sha256.Size}

	// getPCRValues is a variable pointing to a function that returns PCR
	// values.  Using a variable allows us to easily mock the function in our
	// unit tests.
	getPCRValues = func() (map[uint][]byte, error) { return _getPCRValues() }

	// identityPCRs contains the PCR indices that AWS Nitro Enclaves populates:
	// https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html
	//   - PCR0: Enclave image file
	//   - PCR1: Linux kernel and bootstrap
	//   - PCR2: Application
	//   - PCR3: IAM role assigned to the parent instance
	//   - PCR8: Enclave image file signing certificate
	//
	// PCR4 (parent instance ID) is excluded because enclaves run on different
	// parent instances during horizontal scaling.
	identityPCRs = [...]uint{0, 1, 2, 3, 8}
)

// AttestationHashes contains hashes over public key material which we embed in
// the enclave's attestation document for clients to verify.
type AttestationHashes struct {
	tlsKeyHash [sha256.Size]byte // Always set.
	appKeyHash [sha256.Size]byte // Sometimes set, depending on application.
}

// Serialize returns a byte slice that contains our concatenated hashes.
// hashPrefix defines the hash type and length.  Note that all hashes are
// always present.  If a hash was not initialized, it's set to 0-bytes.
func (a *AttestationHashes) Serialize() []byte {
	ser := []byte{}
	ser = append(ser, append(hashPrefix, a.tlsKeyHash[:]...)...)
	ser = append(ser, append(hashPrefix, a.appKeyHash[:]...)...)
	return ser
}

// _getPCRValues returns the enclave's platform configuration register (PCR)
// values.
func _getPCRValues() (map[uint][]byte, error) {
	rawAttDoc, err := newNitroAttester().createAttstn(nil)
	if err != nil {
		return nil, err
	}

	res, err := nitrite.Verify(rawAttDoc, nitrite.VerifyOptions{})
	if err != nil {
		return nil, err
	}

	return res.Document.PCRs, nil
}

// arePCRsIdentical returns true if (and only if) the two given PCR maps
// contain identical values for the Nitro Enclave-populated PCRs.
func arePCRsIdentical(ourPCRs, theirPCRs map[uint][]byte) bool {
	for _, pcr := range identityPCRs {
		ourValue, ourExists := ourPCRs[pcr]
		theirValue, theirExists := theirPCRs[pcr]
		if ourExists != theirExists {
			return false
		}
		if !bytes.Equal(ourValue, theirValue) {
			return false
		}
	}
	return true
}
