package main

import (
	"net/http"
	"net/url"
	"testing"
)

var mockKey = []byte("mock key material")

func TestSliceToNonce(t *testing.T) {
	var err error

	_, err = sliceToNonce([]byte("foo"))
	assertEqual(t, err, errBadSliceLen)

	_, err = sliceToNonce(make([]byte, nonceLen))
	assertEqual(t, err, nil)
}

func TestRequestAndStoreKeyFromApp(t *testing.T) {
	var mockAppRequests []mockAppRequestInfo
	mockServer := createMockServer(mockKey, &mockAppRequests)
	defer mockServer.Close()

	appURL, err := url.Parse(mockServer.URL)
	if err != nil {
		t.Fatalf("Failed to get mock server URL: %v", err)
	}
	keys := enclaveKeys{}

	err = requestAndStoreKeyFromApp(appURL, &keys)
	if err != nil {
		t.Fatalf("Request and store request failed: %v", err)
	}

	assertEqual(t, len(mockAppRequests), 1)
	assertEqual(t, mockAppRequests[0].method, http.MethodGet)
	assertEqual(t, mockAppRequests[0].path, "/enclave/state")

	assertEqual(t, string(keys.getAppKeys()), string(mockKey))
}

func TestSendKeyToApp(t *testing.T) {
	var mockAppRequests []mockAppRequestInfo
	mockServer := createMockServer(nil, &mockAppRequests)
	defer mockServer.Close()

	appURL, err := url.Parse(mockServer.URL)
	if err != nil {
		t.Fatalf("Failed to get mock server URL: %v", err)
	}
	keys := &enclaveKeys{}
	keys.setAppKeys(mockKey)

	err = sendKeyToApp(appURL, keys)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	assertEqual(t, len(mockAppRequests), 1)
	assertEqual(t, mockAppRequests[0].method, http.MethodPut)
	assertEqual(t, mockAppRequests[0].path, "/enclave/state")
	assertEqual(t, string(mockAppRequests[0].body), string(mockKey))
}
