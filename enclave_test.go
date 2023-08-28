package main

import (
	"context"
	"testing"
)

var defaultCfg = Config{
	FQDN:          "example.com",
	ExtPubPort:    50000,
	ExtPrivPort:   50001,
	IntPort:       50002,
	HostProxyPort: 1024,
	UseACME:       false,
	Debug:         true,
	FdCur:         1024,
	FdMax:         4096,
	WaitForApp:    true,
}

func assertEqual(t *testing.T, is, should interface{}) {
	t.Helper()
	if should != is {
		t.Fatalf("Expected value\n%v\nbut got\n%v", should, is)
	}
}

func createEnclave(cfg *Config) *Enclave {
	e, err := NewEnclave(context.Background(), cfg)
	if err != nil {
		panic(err)
	}
	return e
}

func TestValidateConfig(t *testing.T) {
	var err error
	var c Config

	if err = c.Validate(); err == nil {
		t.Fatalf("Validation of invalid config did not return an error.")
	}

	// Set one required field but leave others unset.
	c.FQDN = "example.com"
	if err = c.Validate(); err == nil {
		t.Fatalf("Validation of invalid config did not return an error.")
	}

	// Set the remaining required fields.
	c.ExtPubPort = 1
	c.ExtPrivPort = 1
	c.IntPort = 1
	c.HostProxyPort = 1
	if err = c.Validate(); err != nil {
		t.Fatalf("Validation of valid config returned an error.")
	}
}

func TestGenSelfSignedCert(t *testing.T) {
	e := createEnclave(&defaultCfg)
	if err := e.genSelfSignedCert(); err != nil {
		t.Fatalf("Failed to create self-signed certificate: %s", err)
	}
}
