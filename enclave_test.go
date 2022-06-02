package nitriding

import (
	"testing"
)

func createEnclave() *Enclave {
	cfg := &Config{
		SOCKSProxy: "socks5://127.0.0.1:1080",
		FQDN:       "example.com",
		Port:       50000,
		UseACME:    false,
		Debug:      false,
		FdCur:      1024,
		FdMax:      4096,
	}
	return NewEnclave(cfg)
}

func TestGenSelfSignedCert(t *testing.T) {
	e := createEnclave()
	if err := e.genSelfSignedCert(); err != nil {
		t.Fatalf("Failed to create self-signed certificate: %s", err)
	}
}
