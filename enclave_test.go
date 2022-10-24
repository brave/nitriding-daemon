package nitriding

import (
	"errors"
	"testing"
)

func createEnclave() *Enclave {
	cfg := &Config{
		FQDN:    "example.com",
		Port:    50000,
		UseACME: false,
		Debug:   false,
		FdCur:   1024,
		FdMax:   4096,
	}
	e, err := NewEnclave(cfg)
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

	// Set the last required field.
	c.Port = 1
	if err = c.Validate(); err != nil {
		t.Fatalf("Validation of valid config returned an error.")
	}
}

func TestGenSelfSignedCert(t *testing.T) {
	e := createEnclave()
	if err := e.genSelfSignedCert(); err != nil {
		t.Fatalf("Failed to create self-signed certificate: %s", err)
	}
}

func TestKeyMaterial(t *testing.T) {
	e := createEnclave()
	k := struct{ Foo string }{"foobar"}

	if _, err := e.KeyMaterial(); err != errNoKeyMaterial {
		t.Fatal("Expected error because we're trying to retrieve non-existing key material.")
	}

	e.SetKeyMaterial(k)
	r, err := e.KeyMaterial()
	if err != nil {
		t.Fatalf("Failed to retrieve key material: %s", err)
	}
	if r != k {
		t.Fatal("Retrieved key material is unexpected.")
	}
}

func TestSetupAcme(t *testing.T) {
	e := createEnclave()

	// Our autocert code is difficult to test.  Simply run it until we hit the
	// first error.  Better than testing nothing.
	expectedErr := errHTTP01Failed
	if err := e.setupAcme(); !errors.Is(err, expectedErr) {
		t.Fatalf("Expected error %v but got %v.", expectedErr, err)
	}
}
