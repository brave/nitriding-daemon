package nitriding

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/hf/nitrite"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

const (
	nonceLen       = 20           // The size of a nonce in bytes.
	nonceNumDigits = nonceLen * 2 // The number of hex digits in a nonce.
	maxAttDocLen   = 5000         // A (reasonable?) upper limit for attestation doc lengths.
)

var (
	errMethodNotGET      = "only HTTP GET requests are allowed"
	errBadForm           = "failed to parse POST form data"
	errNoNonce           = "could not find nonce in URL query parameters"
	errBadNonceFormat    = fmt.Sprintf("unexpected nonce format; must be %d-digit hex string", nonceNumDigits)
	errFailedAttestation = "failed to obtain attestation document from hypervisor"
	nonceRegExp          = fmt.Sprintf("[a-f0-9]{%d}", nonceNumDigits)

	// getPCRValues is a variable pointing to a function that returns PCR
	// values.  Using a variable allows us to easily mock the function in our
	// unit tests.
	getPCRValues = func() (map[uint][]byte, error) { return _getPCRValues() }
)

// getAttestationHandler takes as input a SHA-256 hash over an HTTPS
// certificate and returns a HandlerFunc.  This HandlerFunc expects a nonce in
// the URL query parameters and subsequently asks its hypervisor for an
// attestation document that contains both the nonce and the certificate hash.
// The resulting Base64-encoded attestation document is then returned to the
// requester.
func getAttestationHandler(certHash *[32]byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, errMethodNotGET, http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, errBadForm, http.StatusBadRequest)
			return
		}

		nonce := r.URL.Query().Get("nonce")
		if nonce == "" {
			http.Error(w, errNoNonce, http.StatusBadRequest)
			return
		}
		if valid, _ := regexp.MatchString(nonceRegExp, nonce); !valid {
			http.Error(w, errBadNonceFormat, http.StatusBadRequest)
			return
		}
		// Decode hex-encoded nonce.
		rawNonce, err := hex.DecodeString(nonce)
		if err != nil {
			http.Error(w, errBadNonceFormat, http.StatusBadRequest)
			return
		}

		rawDoc, err := attest(rawNonce, certHash[:], nil)
		if err != nil {
			http.Error(w, errFailedAttestation, http.StatusInternalServerError)
			return
		}
		b64Doc := base64.StdEncoding.EncodeToString(rawDoc)
		fmt.Fprintln(w, b64Doc)
	}
}

// _getPCRValues returns the enclave's platform configuration register (PCR)
// values.
func _getPCRValues() (map[uint][]byte, error) {
	rawAttDoc, err := attest(nil, nil, nil)
	if err != nil {
		return nil, err
	}

	res, err := nitrite.Verify(rawAttDoc, nitrite.VerifyOptions{})
	if err != nil {
		return nil, err
	}

	return res.Document.PCRs, nil
}

// arePCRsIdentical returns true if (and only if) the two given PCR maps are
// identical.
func arePCRsIdentical(ourPCRs, theirPCRs map[uint][]byte) bool {
	if len(ourPCRs) != len(theirPCRs) {
		return false
	}

	for pcr, ourValue := range ourPCRs {
		theirValue, exists := theirPCRs[pcr]
		if !exists {
			return false
		}
		if !bytes.Equal(ourValue, theirValue) {
			return false
		}
	}
	return true
}

// attest takes as input a nonce, user-provided data and a public key, and then
// asks the Nitro hypervisor to return a signed attestation document that
// contains all three values.
func attest(nonce, userData, publicKey []byte) ([]byte, error) {
	s, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err = s.Close(); err != nil {
			elog.Printf("Attestation: Failed to close default NSM session: %s", err)
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
