package main

import (
	"flag"
	"log"
	"net/url"
	"os"

	"github.com/brave/nitriding"
)

var l = log.New(os.Stderr, "nitriding-cmd: ", log.Ldate|log.Ltime|log.LUTC|log.Lshortfile)

func main() {
	var sockAddr, fqdn, appURL, appWebSrv string
	var port, hostProxyPort int
	var useACME bool
	var u *url.URL
	var err error

	flag.StringVar(&fqdn, "fqdn", "",
		"FQDN of the enclave application (e.g., \"example.com\").")
	flag.StringVar(&sockAddr, "sockaddr", "/tmp/nitriding.sock",
		"Path to Unix domain socket for enclave-internal IPC.")
	flag.StringVar(&appURL, "appurl", "",
		"Code repository of the enclave application (e.g., \"github.com/foo/bar\").")
	flag.StringVar(&appWebSrv, "appwebsrv", "",
		"Enclave-internal HTTP server of the enclave application (e.g., \"http://127.0.0.1:8080\").")
	flag.IntVar(&port, "port", 8443,
		"Nitriding's VSOCK-facing HTTPS port.  Must match port forwarding rules on EC2 host.")
	flag.IntVar(&hostProxyPort, "host-proxy-port", 1024,
		"Port of proxy application running on EC2 host.")
	flag.BoolVar(&useACME, "acme", false,
		"Use Let's Encrypt's ACME to fetch HTTPS certificate.")
	flag.Parse()

	if useACME && fqdn == "" {
		l.Fatalf("Fully qualified domain name not given.  Use the -fqdn flag.")
	}

	if appWebSrv != "" {
		u, err = url.Parse(appWebSrv)
		if err != nil {
			l.Fatalf("Failed to parse URL of Web server: %v", err)
		}
	}

	enclave, err := nitriding.NewEnclave(
		&nitriding.Config{
			FQDN:          fqdn,
			Port:          port,
			HostProxyPort: hostProxyPort,
			UseACME:       useACME,
			SockAddr:      sockAddr,
			AppURL:        appURL,
			AppWebSrv:     u,
		},
	)
	if err != nil {
		l.Fatalf("Failed to create enclave: %v", err)
	}

	if err := enclave.Start(); err != nil {
		l.Fatalf("Enclave terminated: %v", err)
	}

	// Block on this read forever.
	<-make(chan struct{})
}
