package main

import (
	"flag"
	"log"
	"net/url"
	"os"

	"github.com/brave/nitriding"
)

const (
	uint16Max = 0xffff
	uint32Max = 0xffffffff
)

var l = log.New(os.Stderr, "nitriding-cmd: ", log.Ldate|log.Ltime|log.LUTC|log.Lshortfile)

func main() {
	var fqdn, appURL, appWebSrv string
	var extPort, intPort int
	var hostProxyPort int64
	var useACME bool
	var err error

	flag.StringVar(&fqdn, "fqdn", "",
		"FQDN of the enclave application (e.g., \"example.com\").")
	flag.StringVar(&appURL, "appurl", "",
		"Code repository of the enclave application (e.g., \"github.com/foo/bar\").")
	flag.StringVar(&appWebSrv, "appwebsrv", "",
		"Enclave-internal HTTP server of the enclave application (e.g., \"http://127.0.0.1:8081\").")
	flag.IntVar(&extPort, "extport", 8443,
		"Nitriding's VSOCK-facing HTTPS port.  Must match port forwarding rules on EC2 host.")
	flag.IntVar(&intPort, "intport", 8080,
		"Nitriding's enclave-internal HTTP port.  Only used by the enclave application.")
	flag.Int64Var(&hostProxyPort, "host-proxy-port", 1024,
		"Port of proxy application running on EC2 host.")
	flag.BoolVar(&useACME, "acme", false,
		"Use Let's Encrypt's ACME to fetch HTTPS certificate.")
	flag.Parse()

	if fqdn == "" {
		l.Fatalf("-fqdn must be set.")
	}
	if extPort < 1 || extPort > uint16Max {
		l.Fatalf("-extport must be in interval [1, %d]", uint16Max)
	}
	if intPort < 1 || intPort > uint16Max {
		l.Fatalf("-intport must be in interval [1, %d]", uint16Max)
	}
	if hostProxyPort < 1 || hostProxyPort > uint32Max {
		l.Fatalf("-host-proxy-port must be in interval [1, %d]", uint32Max)
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
