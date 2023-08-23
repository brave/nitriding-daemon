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
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"time"
)

const (
	// The endpoint of AWS's Instance Metadata Service, which allows an enclave
	// to learn its internal hostname:
	// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
	metadataSvcToken = "http://169.254.169.254/latest/api/token"
	metadataSvcInfo  = "http://169.254.169.254/latest/meta-data/local-hostname"
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

// getHostnameOrDie returns the "enclave"'s hostname (or IP address) or dies
// trying.  If inside an enclave, we query AWS's Instance Metadata Service.  If
// outside an enclave, we pick whatever IP address the operating system would
// choose when talking to a public IP address.
func getHostnameOrDie() (hostname string) {
	defer func() {
		elog.Printf("Determined our hostname: %s", hostname)
	}()
	var err error

	if !inEnclave {
		hostname = getLocalAddr()
		return
	}

	// We cannot easily tell when all components are in place to receive
	// incoming connections.  We therefore make five attempts to get our
	// hostname from IMDS while waiting for one second in between attempts.
	const retries = 5
	for i := 0; i < retries; i++ {
		hostname, err = getLocalEC2Hostname()
		if err == nil {
			return
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		elog.Fatalf("Error obtaining hostname from IMDSv2: %v", err)
	}
	return
}

func getLocalAddr() string {
	const target = "1.1.1.1:53"
	conn, err := net.Dial("udp", target)
	if err != nil {
		elog.Fatalf("Error dialing %s: %v", target, err)
	}
	defer conn.Close()

	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		elog.Fatalf("Error extracing host: %v", err)
	}
	return host
}

func getLocalEC2Hostname() (string, error) {
	// IMDSv2, which we are using, is session-oriented (God knows why), so we
	// first obtain a session token from the service.
	req, err := http.NewRequest(http.MethodPut, metadataSvcToken, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "10")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	token := string(body)

	// Having obtained the session token, we can now make the actual metadata
	// request.
	req, err = http.NewRequest(http.MethodGet, metadataSvcInfo, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token", token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
