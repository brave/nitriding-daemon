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
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/mdlayher/vsock"

	"github.com/brave/nitriding/randseed"
	"github.com/brave/viproxy"
	"golang.org/x/crypto/acme/autocert"
)

const (
	acmeCertCacheDir    = "cert-cache"
	certificateOrg      = "Brave Software"
	certificateValidity = time.Hour * 24 * 356
	// parentCID determines the CID (analogous to an IP address) of the parent
	// EC2 instance.  According to the AWS docs, it is always 3:
	// https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html
	parentCID = 3
	// parentProxyPort determines the TCP port of the SOCKS proxy that's
	// running on the parent EC2 instance.
	parentProxyPort = 1080
	pathNonce       = "/nonce"
	pathAttestation = "/attestation"
	pathKeys        = "/keys"
	pathRoot        = "/"
)

var (
	elog             = log.New(os.Stderr, "nitriding: ", log.Ldate|log.Ltime|log.LUTC|log.Lshortfile)
	errNoKeyMaterial = errors.New("no key material registered")
)

// Enclave represents a service running inside an AWS Nitro Enclave.
type Enclave struct {
	sync.RWMutex
	cfg         *Config
	httpSrv     http.Server
	router      *chi.Mux
	certFpr     [sha256.Size]byte
	nonceCache  *cache
	keyMaterial any
}

// Config represents the configuration of our enclave service.
type Config struct {
	SOCKSProxy string
	FQDN       string
	Port       int
	UseACME    bool
	Debug      bool
	FdCur      uint64
	FdMax      uint64
	AppURL     string
}

// NewEnclave creates and returns a new enclave with the given config.
func NewEnclave(cfg *Config) *Enclave {
	r := chi.NewRouter()
	e := &Enclave{
		cfg:    cfg,
		router: r,
		httpSrv: http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.Port),
			Handler: r,
		},
		nonceCache: newCache(defaultItemExpiry),
	}
	if cfg.Debug {
		e.router.Use(middleware.Logger)
	}

	return e
}

// Start starts the Nitro Enclave.  If it bootstraps correctly, this function
// won't return because it starts an HTTPS server.  If something goes wrong,
// the function returns an error.
func (e *Enclave) Start() error {
	var err error
	errPrefix := "failed to start Nitro Enclave"

	inEnclave, err := randseed.InEnclave()
	if err != nil {
		return fmt.Errorf("%s: couldn't determine if we're in enclave: %w", errPrefix, err)
	}
	if inEnclave {
		if err = assignLoAddr(); err != nil {
			return fmt.Errorf("%s: failed to assign loopback address: %w", errPrefix, err)
		}
		elog.Println("Assigned address to lo interface.")
	}

	// Set file descriptor limit.  There's no need to exit if this fails.
	if err = setFdLimit(e.cfg.FdCur, e.cfg.FdMax); err != nil {
		elog.Printf("Failed to set new file descriptor limit: %s", err)
	}

	// Get an HTTPS certificate.
	if e.cfg.UseACME {
		err = e.setupAcme()
	} else {
		err = e.genSelfSignedCert()
	}
	if err != nil {
		return fmt.Errorf("%s: failed to create certificate: %w", errPrefix, err)
	}
	if inEnclave {
		e.router.Get(pathAttestation, getAttestationHandler(&e.certFpr))
	}
	e.router.Get(pathNonce, getNonceHandler(e))
	e.router.Get(pathKeys, getKeysHandler(e, time.Now))
	e.router.Get(pathRoot, getIndexHandler(e.cfg))

	// Tell Go's HTTP library to use SOCKS proxy for both HTTP and HTTPS.
	if err := os.Setenv("HTTP_PROXY", e.cfg.SOCKSProxy); err != nil {
		return fmt.Errorf("%s: failed to set env var: %w", errPrefix, err)
	}
	if err := os.Setenv("HTTPS_PROXY", e.cfg.SOCKSProxy); err != nil {
		return fmt.Errorf("%s: failed to set env var: %w", errPrefix, err)
	}

	// Set up AF_INET to AF_VSOCK proxy to facilitate the use of the SOCKS
	// proxy.
	u, err := url.Parse(e.cfg.SOCKSProxy)
	if err != nil {
		return fmt.Errorf("failed to parse SOCKSProxy from config: %w", err)
	}
	inAddr, err := net.ResolveTCPAddr("tcp", u.Host)
	if err != nil {
		return fmt.Errorf("failed to resolve SOCKSProxy from config: %w", err)
	}
	tuple := &viproxy.Tuple{
		InAddr:  inAddr,
		OutAddr: &vsock.Addr{ContextID: uint32(parentCID), Port: uint32(parentProxyPort)},
	}
	proxy := viproxy.NewVIProxy([]*viproxy.Tuple{tuple})
	if err := proxy.Start(); err != nil {
		return fmt.Errorf("failed to start VIProxy: %w", err)
	}

	elog.Printf("Starting Web server on port %s.", e.httpSrv.Addr)
	var l net.Listener
	inEnclave, err = randseed.InEnclave()
	if err != nil {
		return fmt.Errorf("%s: couldn't determine if we're in enclave: %w", errPrefix, err)
	}

	// Finally, start the Web server.  If we're inside an enclave, we use a
	// vsock-enabled listener, otherwise a simple tcp listener.
	if inEnclave {
		l, err = vsock.Listen(uint32(e.cfg.Port), nil)
		if err != nil {
			return fmt.Errorf("%s: failed to create vsock listener: %w", errPrefix, err)
		}
		defer func() {
			_ = l.Close()
		}()

		return e.httpSrv.ServeTLS(l, "", "")
	}
	l, err = net.Listen("tcp", e.httpSrv.Addr)
	if err != nil {
		return fmt.Errorf("%s: failed to create tcp listener: %w", errPrefix, err)
	}
	defer func() {
		_ = l.Close()
	}()
	return e.httpSrv.ServeTLS(l, "", "")
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

	e.httpSrv.TLSConfig = &tls.Config{
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
	var cache autocert.Cache
	if err = os.MkdirAll(acmeCertCacheDir, 0700); err != nil {
		return fmt.Errorf("Failed to create cache directory: %w", err)
	}
	cache = autocert.DirCache(acmeCertCacheDir)
	certManager := autocert.Manager{
		Cache:      cache,
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist([]string{e.cfg.FQDN}...),
	}
	go func() {
		// Let's Encrypt's HTTP-01 challenge requires a listener on port 80:
		// https://letsencrypt.org/docs/challenge-types/#http-01-challenge
		var l net.Listener
		inEnclave, err := randseed.InEnclave()
		if err != nil {
			elog.Fatalf("Couldn't determine if we're in enclave: %s", err)
		}

		if inEnclave {
			l, err = vsock.Listen(uint32(80), nil)
			if err != nil {
				elog.Fatalf("Failed to listen for HTTP-01 challenge: %s", err)
			}
			defer func() {
				_ = l.Close()
			}()
		} else {
			l, err = net.Listen("tcp", ":80")
			if err != nil {
				elog.Fatalf("Failed to listen for HTTP-01 challenge: %s", err)
			}
		}

		elog.Print("Starting autocert listener.")
		_ = http.Serve(l, certManager.HTTPHandler(nil))
	}()
	e.httpSrv.TLSConfig = &tls.Config{GetCertificate: certManager.GetCertificate}

	go func() {
		// Wait until the HTTP-01 listener returned and then check if our new
		// certificate is cached.
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
				e.certFpr = sha256.Sum256(cert.Raw)
				elog.Printf("Set SHA-256 fingerprint of server's certificate to: %x", e.certFpr[:])
				return nil
			}
		}
		rawData = rest
	}
	return nil
}

// AddRoute adds an HTTP handler for the given HTTP method and pattern.
func (e *Enclave) AddRoute(method, pattern string, handlerFn http.HandlerFunc) {
	switch method {
	case http.MethodGet:
		e.router.Get(pattern, handlerFn)
	case http.MethodHead:
		e.router.Head(pattern, handlerFn)
	case http.MethodPost:
		e.router.Post(pattern, handlerFn)
	case http.MethodPut:
		e.router.Put(pattern, handlerFn)
	case http.MethodPatch:
		e.router.Patch(pattern, handlerFn)
	case http.MethodDelete:
		e.router.Delete(pattern, handlerFn)
	case http.MethodConnect:
		e.router.Connect(pattern, handlerFn)
	case http.MethodOptions:
		e.router.Options(pattern, handlerFn)
	case http.MethodTrace:
		e.router.Trace(pattern, handlerFn)
	}
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
