package main

import (
	"flag"
	"log"
	"math"
	"net/url"
	"os"

	"github.com/brave/nitriding"
)

var l = log.New(os.Stderr, "nitriding-cmd: ", log.Ldate|log.Ltime|log.LUTC|log.Lshortfile)

func main() {
	var fqdn, appURL, appWebSrv string
	var extPort, intPort, hostProxyPort uint
	var useACME bool
	var err error

	flag.StringVar(&fqdn, "fqdn", "",
		"FQDN of the enclave application (e.g., \"example.com\").")
	flag.StringVar(&appURL, "appurl", "",
		"Code repository of the enclave application (e.g., \"github.com/foo/bar\").")
	flag.StringVar(&appWebSrv, "appwebsrv", "",
		"Enclave-internal HTTP server of the enclave application (e.g., \"http://127.0.0.1:8081\").")
	flag.UintVar(&extPort, "extport", 8443,
		"Nitriding's VSOCK-facing HTTPS port.  Must match port forwarding rules on EC2 host.")
	flag.UintVar(&intPort, "intport", 8080,
		"Nitriding's enclave-internal HTTP port.  Only used by the enclave application.")
	flag.UintVar(&hostProxyPort, "host-proxy-port", 1024,
		"Port of proxy application running on EC2 host.")
	flag.BoolVar(&useACME, "acme", false,
		"Use Let's Encrypt's ACME to fetch HTTPS certificate.")
	flag.Parse()

	if fqdn == "" {
		l.Fatalf("-fqdn must be set.")
	}
	if extPort < 1 || extPort > math.MaxUint16 {
		l.Fatalf("-extport must be in interval [1, %d]", math.MaxUint16)
	}
	if intPort < 1 || intPort > math.MaxUint16 {
		l.Fatalf("-intport must be in interval [1, %d]", math.MaxUint16)
	}
	if hostProxyPort < 1 || hostProxyPort > math.MaxUint32 {
		l.Fatalf("-host-proxy-port must be in interval [1, %d]", math.MaxUint32)
	}

	c := &nitriding.Config{
		FQDN:          fqdn,
		ExtPort:       uint16(extPort),
		IntPort:       uint16(intPort),
		HostProxyPort: uint32(hostProxyPort),
		UseACME:       useACME,
	}
	if appURL != "" {
		u, err := url.Parse(appURL)
		if err != nil {
			l.Fatalf("Failed to parse application URL: %v", err)
		}
		c.AppURL = u
	}
	if appWebSrv != "" {
		u, err := url.Parse(appWebSrv)
		if err != nil {
			l.Fatalf("Failed to parse URL of Web server: %v", err)
		}
		c.AppWebSrv = u
	}

	enclave, err := nitriding.NewEnclave(c)
	if err != nil {
		l.Fatalf("Failed to create enclave: %v", err)
	}

	if err := enclave.Start(); err != nil {
		l.Fatalf("Enclave terminated: %v", err)
	}

	// Block on this read forever.
	<-make(chan struct{})
}
