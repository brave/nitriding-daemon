package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"time"
)

var (
	errBadSliceLen               = errors.New("slice is not of same length as nonce")
	newUnauthenticatedHTTPClient = func() *http.Client {
		return _newUnauthenticatedHTTPClient()
	}
	getSyncURL = func(host string, port uint16) *url.URL {
		return _getSyncURL(host, port)
	}
)

// _getSyncURL turns the given host and port into a URL that a leader enclave
// can sync with.
var _getSyncURL = func(host string, port uint16) *url.URL {
	return &url.URL{
		Scheme: "https",
		Host:   fmt.Sprintf("%s:%d", host, port),
		Path:   pathSync,
	}
}

// newUnauthenticatedHTTPClient returns an HTTP client that skips HTTPS
// certificate validation.  In the context of nitriding, this is fine because
// all we need is a *confidential* channel, and not an authenticated channel.
// Authentication is handled via attestation documents.
func _newUnauthenticatedHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: transport}
}

// createCertificate creates a self-signed certificate and returns the
// PEM-encoded certificate and key.  Some of the code below was taken from:
// https://eli.thegreenplace.net/2021/go-https-servers-with-tls/
func createCertificate(fqdn string) (cert []byte, key []byte, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{certificateOrg},
		},
		DNSNames:              []string{fqdn},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(certificateValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return nil, nil, err
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if pemCert == nil {
		return nil, nil, errors.New("error encoding cert as PEM")
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if pemKey == nil {
		return nil, nil, errors.New("error encoding key as PEM")
	}

	return pemCert, pemKey, nil
}

// sliceToNonce copies the given slice into a nonce and returns the nonce.
func sliceToNonce(s []byte) (nonce, error) {
	var n nonce

	if len(s) != nonceLen {
		return nonce{}, errBadSliceLen
	}

	copy(n[:], s[:nonceLen])
	return n, nil
}
