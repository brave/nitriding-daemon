package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	_ "net/http/pprof"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/mdlayher/vsock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/nacl/box"
)

// TODO: Support Let's Encrypt (if we choose to).
// TODO: Handle key sync error edge cases.
// TODO: Handle the case of the leader restarting.  Workers must not break.

const (
	acmeCertCacheDir    = "cert-cache"
	certificateOrg      = "AWS Nitro enclave application"
	certificateValidity = time.Hour * 24 * 356
	// parentCID determines the CID (analogous to an IP address) of the parent
	// EC2 instance.  According to the AWS docs, it is always 3:
	// https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html
	parentCID = 3
	// The following paths are handled by nitriding.
	pathRoot         = "/enclave"
	pathNonce        = "/enclave/nonce"
	pathAttestation  = "/enclave/attestation"
	pathState        = "/enclave/state"
	pathSync         = "/enclave/sync"
	pathHash         = "/enclave/hash"
	pathReady        = "/enclave/ready"
	pathProfiling    = "/enclave/debug"
	pathConfig       = "/enclave/config"
	pathLeader       = "/enclave/leader"
	pathRegistration = "/enclave/registration"
	// All other paths are handled by the enclave application's Web server if
	// it exists.
	pathProxy = "/*"
)

var (
	errNoKeyMaterial  = errors.New("no key material registered")
	errCfgMissingFQDN = errors.New("given config is missing FQDN")
	errCfgMissingPort = errors.New("given config is missing port")
)

// enclaveKeys holds key material for nitriding itself (the HTTPS certificate)
// and for the enclave application (whatever the application wants to "store"
// in nitriding).  All these keys are meant to be managed by a leader enclave
// and -- if horizontal scaling is required -- synced to worker enclaves.
type enclaveKeys struct {
	// TODO: Add another field that contains high-entropy bytes.
	NitridingKey  []byte `json:"nitriding_key"`
	NitridingCert []byte `json:"nitriding_cert"`
	AppKeys       []byte `json:"app_keys"`
}

// hashAndB64 returns the Base64-encoded hash over our key material.  The
// resulting string is not confidential as it's impractical to reverse the key
// material.
func (e *enclaveKeys) hashAndB64() string {
	keys := append(append(e.NitridingCert, e.NitridingKey...), e.AppKeys...)
	hash := sha256.Sum256(keys)
	return base64.StdEncoding.EncodeToString(hash[:])
}

// Enclave represents a service running inside an AWS Nitro Enclave.
type Enclave struct {
	sync.RWMutex
	attester
	cfg                   *Config
	extPubSrv, extPrivSrv *http.Server
	intSrv                *http.Server
	promSrv               *http.Server
	revProxy              *httputil.ReverseProxy
	hashes                *AttestationHashes
	promRegistry          *prometheus.Registry
	metrics               *metrics
	workers               *workers
	nonceCache            *cache
	keys                  *enclaveKeys
	ephemeralSyncKeys     *boxKey // TODO
	ready, stop, isLeader chan bool
	httpsCert             *certRetriever
}

// Config represents the configuration of our enclave service.
type Config struct {
	// FQDN contains the fully qualified domain name that's set in the HTTPS
	// certificate of the enclave's Web server, e.g. "example.com".  This field
	// is required.
	FQDN string

	// FQDNLeader contains the fully qualified domain name of the leader
	// enclave, which coordinates enclave synchronization.  Only set this field
	// if horizontal scaling is required.
	FQDNLeader string

	// ExtPubPort contains the TCP port that the public Web server should
	// listen on, e.g. 443.  This port is not *directly* reachable by the
	// Internet but the EC2 host's proxy *does* forward Internet traffic to
	// this port.  This field is required.
	ExtPubPort uint16

	// ExtPrivPort contains the TCP port that the non-public Web server should
	// listen on.  The Web server behind this port exposes confidential
	// endpoints and is therefore only meant to be reachable by the enclave
	// administrator but *not* the public Internet.
	ExtPrivPort uint16

	// IntPort contains the enclave-internal TCP port of the Web server that
	// provides an HTTP API to the enclave application.  This field is
	// required.
	IntPort uint16

	// UseVsockForExtPort must be set to true if direct communication
	// between the host and Web server via VSOCK is desired. The daemon will listen
	// on the enclave's VSOCK address and the port defined in ExtPubPort.
	UseVsockForExtPort bool

	// DisableKeepAlives must be set to true if keep-alive connections
	// should be disabled for the HTTPS service.
	DisableKeepAlives bool

	// HostProxyPort indicates the TCP port of the proxy application running on
	// the EC2 host.  Note that VSOCK ports are 32 bits large.  This field is
	// required.
	HostProxyPort uint32

	// PrometheusPort contains the TCP port of the Web server that exposes
	// Prometheus metrics.  Prometheus metrics only reveal coarse-grained
	// information and are safe to export in production.
	PrometheusPort uint16

	// PrometheusNamespace specifies the namespace for exported Prometheus
	// metrics.  Consider setting this to your application's name.
	PrometheusNamespace string

	// UseProfiling enables profiling via pprof.  Profiling information will be
	// available at /enclave/debug.  Note that profiling data is privacy
	// sensitive and therefore must not be enabled in production.
	UseProfiling bool

	// UseACME must be set to true if you want your enclave application to
	// request a Let's Encrypt-signed certificate.  If this is set to false,
	// the enclave creates a self-signed certificate.
	UseACME bool

	// Debug can be set to true to see debug messages, i.e., if you are
	// starting the enclave in debug mode by running:
	//
	//   nitro-cli run-enclave --debug-mode ....
	//
	// Do not set this to true in production because printing debug messages
	// for each HTTP request slows down the enclave application, and you are
	// not able to see debug messages anyway unless you start the enclave using
	// nitro-cli's "--debug-mode" flag.
	Debug bool

	// FdCur and FdMax set the soft and hard resource limit, respectively.  The
	// default for both variables is 65536.
	FdCur uint64
	FdMax uint64

	// AppURL should be set to the URL of the software repository that's
	// running inside the enclave, e.g., "https://github.com/foo/bar".  The URL
	// is shown on the enclave's index page, as part of instructions on how to
	// do remote attestation.
	AppURL *url.URL

	// AppWebSrv should be set to the enclave-internal Web server of the
	// enclave application, e.g., "http://127.0.0.1:8080".  Nitriding acts as a
	// TLS-terminating reverse proxy and forwards incoming HTTP requests to
	// this Web server.  Note that this configuration option is only necessary
	// if the enclave application exposes an HTTP server.  Non-HTTP enclave
	// applications can ignore this.
	AppWebSrv *url.URL

	// WaitForApp instructs nitriding to wait for the application's signal
	// before launching the Internet-facing Web server.  Set this flag if your
	// application takes a while to bootstrap and you don't want to risk
	// inconsistent state when syncing, or unexpected attestation documents.
	// If set, your application must make the following request when ready:
	//
	//     GET http://127.0.0.1:{IntPort}/enclave/ready
	WaitForApp bool

	// MockCertFp specifies a mock TLS certificate fingerprint
	// to use in attestation documents.
	MockCertFp string
}

// Validate returns an error if required fields in the config are not set.
func (c *Config) Validate() error {
	if c.ExtPubPort == 0 || c.IntPort == 0 || c.HostProxyPort == 0 {
		return errCfgMissingPort
	}
	if c.FQDN == "" {
		return errCfgMissingFQDN
	}
	return nil
}

// isScalingEnabled returns true if horizontal enclave scaling is enabled in our
// enclave configuration.
func (c *Config) isScalingEnabled() bool {
	return c.FQDNLeader != ""
}

// String returns a string representation of the enclave's configuration.
func (c *Config) String() string {
	s, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "failed to marshal enclave config"
	}
	return string(s)
}

// NewEnclave creates and returns a new enclave with the given config.
func NewEnclave(cfg *Config) (*Enclave, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("failed to create enclave: %w", err)
	}

	reg := prometheus.NewRegistry()
	e := &Enclave{
		attester: &dummyAttester{},
		cfg:      cfg,
		extPubSrv: &http.Server{
			Handler: chi.NewRouter(),
		},
		extPrivSrv: &http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.ExtPrivPort),
			Handler: chi.NewRouter(),
		},
		intSrv: &http.Server{
			Addr:    fmt.Sprintf("127.0.0.1:%d", cfg.IntPort),
			Handler: chi.NewRouter(),
		},
		promSrv: &http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.PrometheusPort),
			Handler: promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}),
		},
		httpsCert:    &certRetriever{},
		keys:         &enclaveKeys{},
		promRegistry: reg,
		metrics:      newMetrics(reg, cfg.PrometheusNamespace),
		nonceCache:   newCache(defaultItemExpiry),
		hashes:       new(AttestationHashes),
		workers:      newWorkers(time.Minute),
		stop:         make(chan bool),
		ready:        make(chan bool),
		isLeader:     make(chan bool),
	}

	// Increase the maximum number of idle connections per host.  This is
	// critical to boosting the requests per second that our reverse proxy can
	// sustain.  See the following comment for more details:
	// https://github.com/brave/nitriding-daemon/issues/2#issuecomment-1530245059
	http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 500
	http.DefaultTransport.(*http.Transport).MaxIdleConns = 500

	if cfg.Debug {
		e.extPubSrv.Handler.(*chi.Mux).Use(middleware.Logger)
		e.extPrivSrv.Handler.(*chi.Mux).Use(middleware.Logger)
		e.intSrv.Handler.(*chi.Mux).Use(middleware.Logger)
	}
	if cfg.PrometheusPort > 0 {
		e.extPubSrv.Handler.(*chi.Mux).Use(e.metrics.middleware)
		e.extPrivSrv.Handler.(*chi.Mux).Use(e.metrics.middleware)
		e.intSrv.Handler.(*chi.Mux).Use(e.metrics.middleware)
	}
	if cfg.UseProfiling {
		e.extPubSrv.Handler.(*chi.Mux).Mount(pathProfiling, middleware.Profiler())
	}
	if cfg.DisableKeepAlives {
		e.extPubSrv.SetKeepAlivesEnabled(false)
	}

	// Register external public HTTP API.
	m := e.extPubSrv.Handler.(*chi.Mux)
	m.Get(pathAttestation, attestationHandler(e.cfg.UseProfiling, e.hashes))
	m.Get(pathNonce, nonceHandler(e))
	m.Get(pathRoot, rootHandler(e.cfg))
	m.Get(pathConfig, configHandler(e.cfg))

	// Register external but private HTTP API.
	m = e.extPrivSrv.Handler.(*chi.Mux)
	m.Get(pathLeader, leaderHandler(e))
	m.Get(pathSync, initSyncHandler(e))
	m.Post(pathSync, finishSyncHandler(e))

	// Register enclave-internal HTTP API.
	m = e.intSrv.Handler.(*chi.Mux)
	m.Get(pathReady, readyHandler(e))
	m.Get(pathState, getStateHandler(e))
	m.Put(pathState, putStateHandler(e))
	m.Post(pathHash, hashHandler(e))

	// Configure our reverse proxy if the enclave application exposes an HTTP
	// server.
	if cfg.AppWebSrv != nil {
		e.revProxy = httputil.NewSingleHostReverseProxy(cfg.AppWebSrv)
		e.revProxy.BufferPool = newBufPool()
		e.extPubSrv.Handler.(*chi.Mux).Handle(pathProxy, e.revProxy)
		// If we expose Prometheus metrics, we keep track of the HTTP backend's
		// responses.
		if cfg.PrometheusPort > 0 {
			e.revProxy.ModifyResponse = e.metrics.checkRevProxyResp
			e.revProxy.ErrorHandler = e.metrics.checkRevProxyErr
		}
	}

	return e, nil
}

// Start starts the Nitro Enclave.  If something goes wrong, the function
// returns an error.
func (e *Enclave) Start() error {
	var err error
	errPrefix := "failed to start Nitro Enclave"

	if inEnclave {
		// Set file descriptor limit.  There's no need to exit if this fails.
		if err = setFdLimit(e.cfg.FdCur, e.cfg.FdMax); err != nil {
			elog.Printf("Failed to set new file descriptor limit: %s", err)
		}
		if err = configureLoIface(); err != nil {
			return fmt.Errorf("%s: %w", errPrefix, err)
		}
	}

	// Set up our networking environment which creates a TAP device that
	// forwards traffic (via the VSOCK interface) to the EC2 host.
	go runNetworking(e.cfg, e.stop)

	// Get an HTTPS certificate.
	if e.cfg.UseACME {
		err = e.setupAcme()
	} else {
		err = e.genSelfSignedCert()
	}
	if err != nil {
		return fmt.Errorf("%s: failed to create certificate: %w", errPrefix, err)
	}

	if err = e.startWebServers(); err != nil {
		return fmt.Errorf("%s: %w", errPrefix, err)
	}

	// TODO: Ideally, the leader enclave would not call this function.
	if e.cfg.isScalingEnabled() {
		if err := e.syncWithLeader(&url.URL{
			Scheme: "https",
			Host:   fmt.Sprintf("%s:%d", e.cfg.FQDNLeader, e.cfg.ExtPrivPort),
			Path:   pathRegistration,
		}); err != nil {
			elog.Fatalf("Error syncing with leader: %v", err)
		}
		elog.Println("Successfully synced with leader.")
	}

	return nil
}

// Stop stops the enclave.
func (e *Enclave) Stop() error {
	close(e.stop)
	if err := e.intSrv.Shutdown(context.Background()); err != nil {
		return err
	}
	if err := e.extPubSrv.Shutdown(context.Background()); err != nil {
		return err
	}
	if err := e.extPrivSrv.Shutdown(context.Background()); err != nil {
		return err
	}
	if err := e.promSrv.Shutdown(context.Background()); err != nil {
		return err
	}
	return nil
}

// getExtListener returns a listener for the HTTPS service
// via AF_INET or AF_VSOCK.
func (e *Enclave) getExtListener() (net.Listener, error) {
	if e.cfg.UseVsockForExtPort {
		return vsock.Listen(uint32(e.cfg.ExtPubPort), nil)
	} else {
		return net.Listen("tcp", fmt.Sprintf(":%d", e.cfg.ExtPubPort))
	}
}

// startWebServers starts our public-facing Web server, our enclave-internal
// Web server, and -- if desired -- a Web server for profiling and/or metrics.
func (e *Enclave) startWebServers() error {
	if e.cfg.PrometheusPort > 0 {
		elog.Printf("Starting Prometheus Web server (%s).", e.promSrv.Addr)
		go func() {
			err := e.promSrv.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				elog.Fatalf("Prometheus Web server error: %v", err)
			}
		}()
	}

	go func() {
		elog.Printf("Starting internal Web server at %s.", e.intSrv.Addr)
		err := e.intSrv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			elog.Fatalf("Private Web server error: %v", err)
		}
	}()
	go func() {
		elog.Printf("Starting external private Web server at %s.", e.extPrivSrv.Addr)
		err := e.extPrivSrv.ListenAndServeTLS("", "")
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			elog.Fatalf("External private Web server error: %v", err)
		}
	}()
	go func() {
		// If desired, don't launch our Internet-facing Web server until the
		// application signalled that it's ready.
		if e.cfg.WaitForApp {
			<-e.ready
			elog.Println("Application signalled that it's ready.  Starting public Web server.")
		}

		listener, err := e.getExtListener()
		if err != nil {
			elog.Fatalf("Failed to listen on external port: %v", err)
		}

		elog.Printf("Starting external public Web server at :%d.", e.cfg.ExtPubPort)
		err = e.extPubSrv.ServeTLS(listener, "", "")
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			elog.Fatalf("External public Web server error: %v", err)
		}
	}()

	return nil
}

// genSelfSignedCert creates and returns a self-signed TLS certificate based on
// the given FQDN.  Some of the code below was taken from:
// https://eli.thegreenplace.net/2021/go-https-servers-with-tls/
func (e *Enclave) genSelfSignedCert() error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	elog.Println("Generated private key for self-signed certificate.")

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}
	elog.Println("Generated serial number for self-signed certificate.")

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{certificateOrg},
		},
		DNSNames:              []string{e.cfg.FQDN},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(certificateValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}
	elog.Println("Created certificate from template.")

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if pemCert == nil {
		return errors.New("failed to encode certificate to PEM")
	}
	// Determine and set the certificate's fingerprint because we need to add
	// the fingerprint to our Nitro attestation document.
	if err := e.setCertFingerprint(pemCert); err != nil {
		return err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		elog.Fatalf("Unable to marshal private key: %v", err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if pemKey == nil {
		elog.Fatal("Failed to encode key to PEM.")
	}
	e.keys.NitridingKey = pemKey
	e.keys.NitridingCert = pemCert

	cert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		return err
	}
	e.httpsCert.set(&cert)
	e.extPubSrv.TLSConfig = &tls.Config{
		GetCertificate: e.httpsCert.get,
	}
	e.extPrivSrv.TLSConfig = e.extPubSrv.TLSConfig // Both servers share a TLS config.

	return nil
}

// setupAcme attempts to retrieve an HTTPS certificate from Let's Encrypt for
// the given FQDN.  Note that we are unable to cache certificates across
// enclave restarts, so the enclave requests a new certificate each time it
// starts.  If the restarts happen often, we may get blocked by Let's Encrypt's
// rate limiter for a while.
func (e *Enclave) setupAcme() error {
	var err error

	elog.Printf("ACME hostname set to %s.", e.cfg.FQDN)
	// By default, we use an in-memory certificate cache.  We only use the
	// directory cache when we're *not* in an enclave.  There's no point in
	// writing certificates to disk when in an enclave because the disk does
	// not persist when the enclave shuts down.  Besides, dealing with file
	// permissions makes it more complicated to switch to an unprivileged user
	// ID before execution.
	var cache autocert.Cache = newCertCache()
	if !inEnclave {
		cache = autocert.DirCache(acmeCertCacheDir)
	}
	certManager := autocert.Manager{
		Cache:      cache,
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist([]string{e.cfg.FQDN}...),
	}
	e.extPubSrv.TLSConfig = certManager.TLSConfig()

	go func() {
		var rawData []byte
		for {
			// Get the SHA-1 hash over our leaf certificate.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			rawData, err = cache.Get(ctx, e.cfg.FQDN)
			if err != nil {
				time.Sleep(5 * time.Second)
			} else {
				elog.Print("Got certificates from cache.  Proceeding with start.")
				break
			}
		}
		if err := e.setCertFingerprint(rawData); err != nil {
			elog.Fatalf("Failed to set certificate fingerprint: %s", err)
		}
	}()
	return nil
}

// setCertFingerprint takes as input a PEM-encoded certificate and extracts its
// SHA-256 fingerprint.  We need the certificate's fingerprint because we embed
// it in attestation documents, to bind the enclave's certificate to the
// attestation document.
func (e *Enclave) setCertFingerprint(rawData []byte) error {
	if e.cfg.MockCertFp != "" {
		hash, err := hex.DecodeString(e.cfg.MockCertFp)
		if err != nil {
			return errors.New("Failed to decode mock certificate fingerprint hex")
		}
		copy(e.hashes.tlsKeyHash[:], hash)
		return nil
	}
	rest := []byte{}
	for rest != nil {
		block, rest := pem.Decode(rawData)
		if block == nil {
			return errors.New("pem.Decode failed because it didn't find PEM data in the input we provided")
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return err
			}
			if !cert.IsCA {
				e.hashes.tlsKeyHash = sha256.Sum256(cert.Raw)
				elog.Printf("Set SHA-256 fingerprint of server's certificate to: %x",
					e.hashes.tlsKeyHash[:])
				return nil
			}
		}
		rawData = rest
	}
	return nil
}

// SetAppKeys registers the enclave application's key material (e.g., secret
// encryption keys, or what have you), so it can be synchronized with worker
// enclaves.  This is only necessary if horizontal enclave scaling is required.
func (e *Enclave) SetAppKeys(appKeys []byte) {
	e.Lock()
	defer e.Unlock()

	e.keys.AppKeys = appKeys
}

// AppKeys returns the enclave application's key material.  This allows a worker
// enclave to retrieve the key material that it synchronized from the leader
// enclave.
func (e *Enclave) AppKeys() ([]byte, error) {
	e.RLock()
	defer e.RUnlock()

	if e.keys.AppKeys == nil {
		return nil, errNoKeyMaterial
	}
	return e.keys.AppKeys, nil
}

// syncWithLeader is called by worker enclaves to initiate the process of key
// synchronization.  The worker tries to register with the leader for a total of
// one minute, after which it gives up and terminates.
func (e *Enclave) syncWithLeader(leader *url.URL) error {
	elog.Println("Attempting to sync with leader.")

	// Keep on trying every five seconds for a minute.
	ctx, _ := context.WithTimeout(context.Background(), time.Minute)
	ticker := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return errors.New("timed out syncing with leader")
		case <-e.isLeader:
			elog.Println("This enclave became leader.  Aborting key sync.")
			return nil
		case <-ticker.C:
			resp, err := http.Post(leader.String(), "text/plain", nil)
			if err != nil {
				elog.Printf("POST request to leader failed: %v", err)
				break
			}
			if resp.StatusCode != http.StatusOK {
				elog.Printf("Leader returned HTTP code %d.", resp.StatusCode)
				break
			}
			return nil
		}
	}
}

// syncWithWorker is called by the leader enclave right after a worker
// registers itself with the leader enclave.
func (e *Enclave) syncWithWorker(worker *url.URL) error {
	elog.Println("Initiating key synchronization with worker.")

	// Step 1: Create a nonce that the worker must embed in its attestation
	// document to prevent replay attacks.
	nonce, err := newNonce()
	if err != nil {
		return err
	}
	e.nonceCache.Add(nonce.B64())

	// Step 2: Request the worker's attestation document, and provide the
	// previously-generated nonce.
	reqURL := *worker
	reqURL.RawQuery = fmt.Sprintf("nonce=%x", nonce)
	resp, err := http.Get(reqURL.String())
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errNo200(resp.StatusCode)
	}

	// Step 3: Verify the worker's attestation document and extract its
	// auxiliary information.
	b64Attstn, err := io.ReadAll(newLimitReader(resp.Body, maxAttDocLen))
	if err != nil {
		return err
	}
	resp.Body.Close()
	attstn, err := base64.StdEncoding.DecodeString(string(b64Attstn))
	if err != nil {
		return err
	}
	workerAux, err := e.verifyAttstn(attstn, e.nonceCache.Exists)
	if err != nil {
		return err
	}

	// Step 4: Encrypt the leader's enclave keys with the ephemeral public key
	// that the worker put into its auxiliary information.
	pubKey := &[boxKeyLen]byte{}
	copy(pubKey[:], workerAux.(*workerAuxInfo).PublicKey[:])
	jsonKeys, err := json.Marshal(e.keys)
	if err != nil {
		return err
	}
	var encrypted []byte
	encrypted, err = box.SealAnonymous(nil, jsonKeys, pubKey, cryptoRand.Reader)
	if err != nil {
		return err
	}

	// Step 5: Create the leader's auxiliary information, consisting of the
	// worker's nonce and the encrypted enclave keys.
	leaderAux := &leaderAuxInfo{
		WorkersNonce: workerAux.(*workerAuxInfo).WorkersNonce,
		EnclaveKeys:  encrypted,
	}
	attstn, err = e.createAttstn(leaderAux)
	if err != nil {
		return err
	}
	strAttstn := base64.StdEncoding.EncodeToString(attstn)

	// Step 6: Send the leader's attestation document to the worker.
	resp, err = http.Post(worker.String(), "text/plain", strings.NewReader(strAttstn))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errNo200(resp.StatusCode)
	}

	return nil
}
