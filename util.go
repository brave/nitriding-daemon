package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mdlayher/vsock"
)

const (
	maxIPResponseSize     = 32
	maxKeyMaterialSize    = 256 * 1024
	maxHostnameReqSeconds = 5
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

// _newUnauthenticatedHTTPClient returns an HTTP client that skips HTTPS
// certificate validation.  In the context of nitriding, this is fine because
// all we need is a *confidential* channel; not an authenticated channel.
// Authentication is handled on the next layer, using attestation documents.
func _newUnauthenticatedHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
	}
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
// trying.  If inside an enclave, we query the host IP provider, provided by vsock-relay.
// If outside an enclave, we pick whatever IP address the operating system would
// choose when talking to a public IP address.
func getHostnameOrDie(hostIpProviderPort uint32) (hostname string) {
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
	// hostname from the host IP provider while waiting for one second in between attempts.
	const retries = 5
	for i := 0; i < retries; i++ {
		hostname, err = getLocalEC2Hostname(hostIpProviderPort)
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

func getLocalEC2Hostname(hostIpProviderPort uint32) (string, error) {
	conn, err := vsock.Dial(parentCID, hostIpProviderPort, nil)
	if err != nil {
		return "", fmt.Errorf("failed to connect to host ip provider: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(maxHostnameReqSeconds * time.Second))

	data, err := io.ReadAll(newLimitReader(conn, maxIPResponseSize))
	if err != nil {
		return "", fmt.Errorf("failed to read from host ip provider: %w", err)
	}

	hostname := strings.TrimSpace(string(data))

	if hostname == "" {
		return "", fmt.Errorf("received empty ip")
	}

	return hostname, nil
}

func getNonceFromReq(r *http.Request) (nonce, error) {
	if err := r.ParseForm(); err != nil {
		return nonce{}, errBadForm
	}

	strNonce := r.URL.Query().Get("nonce")
	if strNonce == "" {
		return nonce{}, errNoNonce
	}
	strNonce = strings.ToLower(strNonce)
	// Decode hex-encoded nonce.
	rawNonce, err := hex.DecodeString(strNonce)
	if err != nil {
		return nonce{}, errBadNonceFormat
	}

	n, err := sliceToNonce(rawNonce)
	if err != nil {
		return nonce{}, err
	}
	return n, nil
}

func makeLeaderRequest(leader *url.URL, ourNonce nonce, areWeLeader chan bool, errChan chan error) {
	elog.Println("Attempting to talk to leader designation endpoint.")

	reqURL := *leader
	reqURL.RawQuery = fmt.Sprintf("nonce=%x", ourNonce[:])
	resp, err := newUnauthenticatedHTTPClient().Get(reqURL.String())
	if err != nil {
		errChan <- err
		return
	}
	if resp.StatusCode == http.StatusGone {
		// The leader already knows that it's the leader, and it's not us.
		areWeLeader <- false
		return
	}
	errChan <- fmt.Errorf("leader designation endpoint returned %d", resp.StatusCode)
}

func _getAppStateURL(appWebSrv *url.URL) string {
	url := *appWebSrv
	url.Path = pathState
	return url.String()
}

func requestAndStoreKeyFromApp(appWebSrv *url.URL, keys *enclaveKeys) error {
	resp, err := newUnauthenticatedHTTPClient().Get(_getAppStateURL(appWebSrv))
	if err != nil {
		return fmt.Errorf("failed to make get state request: %v", err)
	}
	if resp.StatusCode < 200 && resp.StatusCode >= 300 {
		return fmt.Errorf("get state request returned %v", resp.StatusCode)
	}
	keyMaterial, err := io.ReadAll(newLimitReader(resp.Body, maxKeyMaterialSize))
	if err != nil {
		return fmt.Errorf("failed to read state body: %v", err)
	}
	keys.setAppKeys(keyMaterial)
	return nil
}

func sendKeyToApp(appWebSrv *url.URL, keys *enclaveKeys) error {
	keyMaterial := bytes.NewBuffer(keys.getAppKeys())
	req, err := http.NewRequest(http.MethodPut, _getAppStateURL(appWebSrv), keyMaterial)
	if err != nil {
		return fmt.Errorf("failed to generate request to send key to app: %v", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := newUnauthenticatedHTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("failed to send key to app: %v", err)
	}
	if resp.StatusCode < 200 && resp.StatusCode >= 300 {
		return fmt.Errorf("send key to app request returned %v", resp.StatusCode)
	}
	return nil
}
