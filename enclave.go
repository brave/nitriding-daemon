// Package nitriding implements a lightweight framework to build networked
// Go applications that run in AWS Nitro Enclaves.
package nitriding

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/brave/nitriding/randseed"
	"golang.org/x/crypto/acme/autocert"
)

const (
	acmeCertCacheDir    = "cert-cache"
	certificateOrg      = "AWS Nitro enclave application"
	certificateValidity = time.Hour * 24 * 356
	// parentCID determines the CID (analogous to an IP address) of the parent
	// EC2 instance.  According to the AWS docs, it is always 3:
	// https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html
	parentCID = 3
	// The following paths are handled by nitriding.
	pathRoot        = "/enclave"
	pathNonce       = "/enclave/nonce"
	pathAttestation = "/enclave/attestation"
	pathState       = "/enclave/state"
	pathSync        = "/enclave/sync"
	pathHash        = "/enclave/hash"
	pathReady       = "/enclave/ready"
	// All other paths are handled by the enclave application's Web server if
	// it exists.
	pathProxy = "/*"
)

var (
	elog              = log.New(os.Stderr, "nitriding: ", log.Ldate|log.Ltime|log.LUTC|log.Lshortfile)
	inEnclave         = false
	errNoKeyMaterial  = errors.New("no key material registered")
	errCfgMissingFQDN = errors.New("given config is missing FQDN")
	errCfgMissingPort = errors.New("given config is missing port")
)

// Enclave represents a service running inside an AWS Nitro Enclave.
type Enclave struct {
	sync.RWMutex
	cfg             *Config
	pubSrv, privSrv http.Server
	revProxy        *httputil.ReverseProxy
	hashes          *AttestationHashes
	nonceCache      *cache
	keyMaterial     any
	ready, stop     chan bool
}

// Config represents the configuration of our enclave service.
type Config struct {
	// FQDN contains the fully qualified domain name that's set in the HTTPS
	// certificate of the enclave's Web server, e.g. "example.com".  This field
	// is required.
	FQDN string

	// ExtPort contains the VSOCK-facing TCP port that the Web server should
	// listen on, e.g.  8443.  This port is not *directly* reachable by the
	// Internet but the EC2 host's proxy *does* forward Internet traffic to
	// this port.  This field is required.
	ExtPort uint16

	// IntPort contains the enclave-internal TCP port of the Web server that
	// provides an HTTP API to the enclave application.  This field is
	// required.
	IntPort uint16

	// HostProxyPort indicates the TCP port of the proxy application running on
	// the EC2 host.  Note that VSOCK ports are 32 bits large.  This field is
	// required.
	HostProxyPort uint32

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
}

// Validate returns an error if required fields in the config are not set.
func (c *Config) Validate() error {
	if c.ExtPort == 0 || c.IntPort == 0 || c.HostProxyPort == 0 {
		return errCfgMissingPort
	}
	if c.FQDN == "" {
		return errCfgMissingFQDN
	}
	return nil
}

// init is called once, at package initialization time.
func init() {
	var err error

	// Determine if we're inside an enclave.  Abort execution in the unexpected
	// case that we cannot tell.
	inEnclave, err = randseed.InEnclave()
	if err != nil {
		elog.Fatalf("Failed to determine if we're inside an enclave: %v", err)
	}
	elog.Printf("We're running inside an enclave: %v", inEnclave)
}

// NewEnclave creates and returns a new enclave with the given config.
func NewEnclave(cfg *Config) (*Enclave, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("failed to create enclave: %w", err)
	}

	e := &Enclave{
		cfg: cfg,
		pubSrv: http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.ExtPort),
			Handler: chi.NewRouter(),
		},
		privSrv: http.Server{
			Addr:    fmt.Sprintf("127.0.0.1:%d", cfg.IntPort),
			Handler: chi.NewRouter(),
		},
		nonceCache: newCache(defaultItemExpiry),
		hashes:     new(AttestationHashes),
		stop:       make(chan bool),
		ready:      make(chan bool),
	}

	if cfg.Debug {
		e.pubSrv.Handler.(*chi.Mux).Use(middleware.Logger)
		e.privSrv.Handler.(*chi.Mux).Use(middleware.Logger)
	}

	// Register public HTTP API.
	m := e.pubSrv.Handler.(*chi.Mux)
	m.Get(pathAttestation, attestationHandler(e.hashes))
	m.Get(pathNonce, nonceHandler(e))
	m.Get(pathRoot, rootHandler(e.cfg))
	m.Post(pathSync, respSyncHandler(e))

	// Register enclave-internal HTTP API.
	m = e.privSrv.Handler.(*chi.Mux)
	m.Get(pathSync, reqSyncHandler(e))
	m.Get(pathReady, readyHandler(e))
	m.Get(pathState, getStateHandler(e))
	m.Put(pathState, putStateHandler(e))
	m.Post(pathHash, hashHandler(e))

	// Configure our reverse proxy if the enclave application exposes an HTTP
	// server.
	if cfg.AppWebSrv != nil {
		e.revProxy = httputil.NewSingleHostReverseProxy(cfg.AppWebSrv)
		e.pubSrv.Handler.(*chi.Mux).Handle(pathProxy, proxyHandler(e))
	}

	return e, nil
}

// Start starts the Nitro Enclave.  If something goes wrong, the function
// returns an error.
func (e *Enclave) Start() error {
	var err error
	errPrefix := "failed to start Nitro Enclave"

	// Set file descriptor limit.  There's no need to exit if this fails.
	if inEnclave {
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

	if err = startWebServers(e); err != nil {
		return fmt.Errorf("%s: %w", errPrefix, err)
	}

	return nil
}

// Stop stops the enclave.
func (e *Enclave) Stop() error {
	close(e.stop)
	if err := e.privSrv.Shutdown(context.Background()); err != nil {
		return err
	}
	if err := e.pubSrv.Shutdown(context.Background()); err != nil {
		return err
	}
	return nil
}

// startWebServers starts both our public-facing and our enclave-internal Web
// server in a goroutine.
func startWebServers(e *Enclave) error {
	elog.Printf("Starting public (%s) and private (%s) Web server.", e.pubSrv.Addr, e.privSrv.Addr)

	go e.privSrv.ListenAndServe() //nolint:errcheck
	go func() {
		// If desired, don't launch our Internet-facing Web server until the
		// application signalled that it's ready.
		if e.cfg.WaitForApp {
			<-e.ready
			elog.Println("Application signalled that it's ready.  Starting public Web server.")
		}
		e.pubSrv.ListenAndServeTLS("", "") //nolint:errcheck
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

	cert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		return err
	}

	e.pubSrv.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

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
	e.pubSrv.TLSConfig = certManager.TLSConfig()

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

// SetKeyMaterial registers the enclave's key material (e.g., secret encryption
// keys) as being ready to be synchronized to other, identical enclaves.  Note
// that the key material's underlying data structure must be marshallable to
// JSON.
//
// This is only necessary if you intend to scale enclaves horizontally.  If you
// will only ever run a single enclave, ignore this function.
func (e *Enclave) SetKeyMaterial(keyMaterial any) {
	e.Lock()
	defer e.Unlock()

	e.keyMaterial = keyMaterial
}

// KeyMaterial returns the key material or, if none was registered, an error.
func (e *Enclave) KeyMaterial() (any, error) {
	e.RLock()
	defer e.RUnlock()

	if e.keyMaterial == nil {
		return nil, errNoKeyMaterial
	}
	return e.keyMaterial, nil
}
