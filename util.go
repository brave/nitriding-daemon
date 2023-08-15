package main

import (
	"crypto/tls"
	"net/http"
)

// newUnauthenticatedHTTPClient returns an HTTP client that skips HTTPS
// certificate validation.  In the context of nitriding, this is fine because
// all we need is a *confidential* channel, and not an authenticated channel.
// Authentication is handled via attestation documents.
func newUnauthenticatedHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: transport}
}
