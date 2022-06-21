package nitriding

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"testing"
)

func queryHandler(handler http.HandlerFunc, path string, reader io.Reader) *http.Response {
	req := httptest.NewRequest(http.MethodGet, path, reader)
	rec := httptest.NewRecorder()
	handler(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	return res
}

func TestNonceHandler(t *testing.T) {
	enclave := NewEnclave(&Config{})
	res := queryHandler(getNonceHandler(enclave), pathNonce, bytes.NewReader([]byte{}))

	// Did the operation succeed?
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code %d but got %d.", http.StatusOK, res.StatusCode)
	}

	// Did we get what looks like a nonce?
	b64Nonce, _ := ioutil.ReadAll(res.Body)
	rawNonce, err := base64.StdEncoding.DecodeString(string(b64Nonce))
	if err != nil {
		t.Fatalf("Failed to decode Base64-encoded nonce: %s", err)
	}
	if len(rawNonce) != nonceLen {
		t.Fatalf("Expected nonce length %d but got %d.", nonceLen, len(rawNonce))
	}

	// Was the nonce added to the enclave's nonce cache?
	if !enclave.nonceCache.Exists(strings.TrimSpace(string(b64Nonce))) {
		t.Fatal("Nonce was not added to enclave's nonce cache.")
	}
}

func TestNonceHandlerIfErr(t *testing.T) {
	cryptoRead = func(b []byte) (n int, err error) {
		return 0, errors.New("not enough randomness")
	}
	defer func() {
		cryptoRead = rand.Read
	}()

	res := queryHandler(getNonceHandler(NewEnclave(&Config{})), pathNonce, bytes.NewReader([]byte{}))

	// Did the operation fail?
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("Expected status code %d but got %d.", http.StatusInternalServerError, res.StatusCode)
	}

	// Did we get the correct error string?
	errMsg, _ := ioutil.ReadAll(res.Body)
	if strings.TrimSpace(string(errMsg)) != errFailedNonce {
		t.Fatalf("Expected error message %q but got %q.", errFailedNonce, errMsg)
	}
}

func TestKeysHandler(t *testing.T) {
	var res *http.Response
	enclave := NewEnclave(&Config{})

	// Send non-Base64 bogus data.
	res = queryHandler(getKeysHandler(enclave, time.Now), pathKeys, strings.NewReader("foobar!"))
	expect(t, res, http.StatusInternalServerError, errNoBase64)

	// Send Base64-encoded bogus data.
	res = queryHandler(getKeysHandler(enclave, time.Now), pathKeys, strings.NewReader("Zm9vYmFyCg=="))
	expect(t, res, http.StatusUnauthorized, errFailedVerify)

	// Send an attestation document without any nonce.
	res = queryHandler(getKeysHandler(enclave, attDocNoFieldsTime), pathKeys, strings.NewReader(attDocNoFields))
	expect(t, res, http.StatusUnauthorized, errFailedFindNonce)

	// Send an attestation document with a nonce but no secretbox data.
	enclave.nonceCache.Add("77Ofqd0vUmm6t89uu4vRtxpHXmY=")
	res = queryHandler(getKeysHandler(enclave, attDocNoSbTime), pathKeys, strings.NewReader(attDocNoSb))
	expect(t, res, http.StatusBadRequest, errInvalidSbKeys)

	// Send an attestation document with a nonce and a secretbox key.
}
