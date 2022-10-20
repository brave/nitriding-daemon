package main

import (
	"log"
	"os"

	"github.com/brave/nitriding"
)

func main() {
	log.Printf("Running as UID %d.", os.Getuid())

	enclave := nitriding.NewEnclave(
		&nitriding.Config{
			FQDN:    "nitro.nymity.ch",
			Port:    8080,
			UseACME: false,
			Debug:   true,
		},
	)

	// Start blocks for as long as the enclave is alive.
	if err := enclave.Start(); err != nil {
		log.Fatalf("Enclave terminated: %v", err)
	}
}
