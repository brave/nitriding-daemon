package main

import (
	"flag"
	"log"
	"os"

	"github.com/brave/nitriding"
)

var l = log.New(os.Stderr, "nitriding-cmd: ", log.Ldate|log.Ltime|log.LUTC|log.Lshortfile)

func main() {
	var sockAddr, fqdn, appURL string
	var port, hostProxyPort int
	var useACME bool

	flag.StringVar(&fqdn, "fqdn", "example.com", "FQDN for the enclave application.")
	flag.StringVar(&sockAddr, "sockaddr", "/tmp/nitriding.sock", "Path to unix domain socket for enclave-internal IPC.")
	flag.StringVar(&appURL, "appurl", "github.com/foo/bar", "Code repository for the enclave application.")
	flag.IntVar(&port, "port", 8443, "Nitriding's VSOCK-facing HTTP port.  Must match port forwarding rules on EC2 host.")
	flag.IntVar(&hostProxyPort, "host-proxy-port", 1024, "Port of proxy application running on EC2 host.")
	flag.BoolVar(&useACME, "acme", true, "Use Let's Encrypt's ACME to fetch HTTPS certificate.")
	flag.Parse()

	enclave, err := nitriding.NewEnclave(
		&nitriding.Config{
			FQDN:          fqdn,
			Port:          port,
			HostProxyPort: hostProxyPort,
			UseACME:       useACME,
			SockAddr:      sockAddr,
			AppURL:        appURL,
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
