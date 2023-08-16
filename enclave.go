package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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
)

// TODO: Support Let's Encrypt (if we choose to).
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
	pathHeartbeat    = "/enclave/heartbeat"
	// All other paths are handled by the enclave application's Web server if
	// it exists.
	pathProxy = "/*"
)

var (
	errCfgMissingFQDN = errors.New("given config is missing FQDN")
	errCfgMissingPort = errors.New("given config is missing port")
)

// Enclave represents a service running inside an AWS Nitro Enclave.
type Enclave struct {
	sync.RWMutex
	attester
	ctx                       context.Context
	cfg                       *Config
	extPubSrv, extPrivSrv     *http.Server
	intSrv                    *http.Server
	promSrv                   *http.Server
	revProxy                  *httputil.ReverseProxy
	hashes                    *AttestationHashes
	promRegistry              *prometheus.Registry
	metrics                   *metrics
	workers                   *workers
	keys                      *enclaveKeys
	httpsCert                 *certRetriever
	ready, stop, becameLeader chan struct{}
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
func NewEnclave(ctx context.Context, cfg *Config) (*Enclave, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("failed to create enclave: %w", err)
	}

	reg := prometheus.NewRegistry()
	e := &Enclave{
		attester: &nitroAttester{},
		ctx:      ctx,
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
		hashes:       new(AttestationHashes),
		workers:      newWorkers(time.Minute),
		stop:         make(chan struct{}),
		ready:        make(chan struct{}),
		becameLeader: make(chan struct{}),
	}

	// Increase the maximum number of idle connections per host.  This is
	// critical to boosting the requests per second that our reverse proxy can
	// sustain.  See the following comment for more details:
	// https://github.com/brave/nitriding-daemon/issues/2#issuecomment-1530245059
	http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 500
	http.DefaultTransport.(*http.Transport).MaxIdleConns = 500

	if cfg.Debug {
		e.attester = &dummyAttester{}
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
	m.Get(pathRoot, rootHandler(e.cfg))
	m.Get(pathConfig, configHandler(e.cfg))

	// Register external but private HTTP API.
	m = e.extPrivSrv.Handler.(*chi.Mux)
	m.Get(pathLeader, leaderHandler(ctx, e))
	m.Handle(pathSync, asWorker(e.installKeys, e.becameLeader))

	// Register enclave-internal HTTP API.
	m = e.intSrv.Handler.(*chi.Mux)
	m.Get(pathReady, readyHandler(e))
	m.Get(pathState, getStateHandler(e))
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

// installKeys installs the given enclave keys.  Worker enclaves do this after
// key synchronization.
func (e *Enclave) installKeys(keys *enclaveKeys) error {
	e.keys.set(keys)
	cert, err := tls.X509KeyPair(keys.NitridingCert, keys.NitridingKey)
	if err != nil {
		return err
	}
	e.httpsCert.set(&cert)
	return nil
}

// Start starts the Nitro Enclave.  If something goes wrong, the function
// returns an error.
func (e *Enclave) Start(ctx context.Context) error {
	var (
		err    error
		leader = e.getLeader(pathRegistration)
	)
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

	if e.cfg.isScalingEnabled() {
		err := asWorker(e.installKeys, e.becameLeader).registerWith(leader)
		if err != nil && !errors.Is(err, errBecameLeader) {
			elog.Fatalf("Error syncing with leader: %v", err)
		} else if err == nil {
			go e.workerHeartbeat(ctx)
		}
	}

	return nil
}

// workerHeartbeat periodically talks to the leader enclave to 1) let the leader
// know that we're still alive, and 2) to compare key material.  If it turns out
// that the leader has different key material than the worker, the worker
// re-registers itself, which triggers key re-synchronization.
func (e *Enclave) workerHeartbeat(ctx context.Context) {
	elog.Println("Starting worker's heartbeat loop.")
	defer elog.Println("Exiting worker's heartbeat loop.")
	var (
		leaderHeartbeat    = e.getLeader(pathHeartbeat)
		leaderRegistration = e.getLeader(pathRegistration)
		timer              = time.NewTicker(time.Minute)
	)

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			resp, err := newUnauthenticatedHTTPClient().Post(
				leaderHeartbeat.String(),
				"text/plain",
				strings.NewReader(e.keys.hashAndB64()),
			)
			if err != nil {
				elog.Printf("Error posting heartbeat to leader: %v", err)
				continue
			}
			if resp.StatusCode == http.StatusConflict {
				elog.Println("Our keys are outdated.  Re-synchronizing.")
				err := asWorker(e.installKeys, e.becameLeader).registerWith(leaderRegistration)
				if err != nil && !errors.Is(err, errBecameLeader) {
					elog.Fatalf("Error syncing with leader: %v", err)
				}
				elog.Println("Successfully re-synchronized with leader.")
				continue
			}
			if resp.StatusCode != http.StatusOK {
				elog.Printf("Leader responded to heartbeat with status code %d.", resp.StatusCode)
				continue
			}
			elog.Println("Successfully sent heartbeat to leader.")
		}
	}
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
	e.keys.setNitridingKeys(pemKey, pemCert)

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

// getLeader returns the leader enclave's URL.
func (e *Enclave) getLeader(path string) *url.URL {
	return &url.URL{
		Scheme: "https",
		Host:   fmt.Sprintf("%s:%d", e.cfg.FQDNLeader, e.cfg.ExtPrivPort),
		Path:   path,
	}
}

// getWorker returns the worker enclave's URL from the given HTTP request.
func (e *Enclave) getWorker(r *http.Request) (*url.URL, error) {
	// Go's HTTP server sets RemoteAddr to IP:port:
	// https://pkg.go.dev/net/http#Request
	strIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, err
	}
	return &url.URL{
		Scheme: "https", // Leader and workers use HTTPS to communicate.
		Host:   fmt.Sprintf("%s:%d", strIP, e.cfg.ExtPrivPort),
		Path:   pathSync,
	}, nil
}
