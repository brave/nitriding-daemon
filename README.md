# Nitriding

[![GoDoc](https://pkg.go.dev/badge/github.com/brave/nitriding?utm_source=godoc)](https://pkg.go.dev/github.com/brave/nitriding)

This package helps with building networked Go applications on top of AWS Nitro
Enclaves.  The package provides the following features:

1. Initialize the enclave's entropy pool.

2. Obtain an HTTPS certificate for clients to connect to the enclave; either
   self-signed, or via Let's Encrypt.

3. Expose an endpoint for remote attestation.

4. Start a proxy that transparently translates between IP and VSOCK.

Use the following "hello world" example to get started:

	package main

	import (
		"fmt"
		"log"
		"net/http"

		"github.com/brave/nitriding"
	)

	func helloWorldHandler(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello world")
	}

	func main() {
		enclave := nitriding.NewEnclave(
			&nitriding.Config{
				FQDN:    "example.com",
				Port:    8080,
				UseACME: false,
				Debug:   false,
			},
		)
		enclave.AddRoute(http.MethodGet, "/hello-world", helloWorldHandler)
		if err := enclave.Start(); err != nil {
			log.Fatalf("Enclave terminated: %v", err)
		}
	}
