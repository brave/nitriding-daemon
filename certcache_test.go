package nitriding

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"golang.org/x/crypto/acme/autocert"
)

func TestGet(t *testing.T) {
	var err error
	var key = "foo"
	var expectedCert = []byte("bar")
	c := newCertCache()

	// Retrieve non-existing key.
	_, err = c.Get(context.TODO(), key)
	if !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("Expected error %v but got %v.", autocert.ErrCacheMiss, err)
	}

	// Retrieve existing key.
	_ = c.Put(context.TODO(), key, expectedCert)
	cert, err := c.Get(context.TODO(), key)
	if err != nil {
		t.Fatalf("Expected no error but got %v.", err)
	}
	if !bytes.Equal(expectedCert, cert) {
		t.Fatalf("Expected value %s but got %s.", string(expectedCert), string(cert))
	}
}

func TestPut(t *testing.T) {
	var err error
	var key = "foo"
	var expectedCert = []byte("bar")
	c := newCertCache()

	if err = c.Put(context.TODO(), key, expectedCert); err != nil {
		t.Fatalf("Expected no error but got %v.", err)
	}
}

func TestDelete(t *testing.T) {
	var key = "foo"
	var err error
	c := newCertCache()

	_ = c.Put(context.TODO(), key, []byte("bar"))
	if err = c.Delete(context.TODO(), key); err != nil {
		t.Fatalf("Expected no error but got %v.", err)
	}
	if len(c.cache) != 0 {
		t.Fatal("Expected cache to be empty but it's not.")
	}

	// Try deleting the same element again.  This should not result in an error
	// as our Delete never returns an error.
	if err = c.Delete(context.TODO(), key); err != nil {
		t.Fatalf("Expected no error but got %v.", err)
	}
	if len(c.cache) != 0 {
		t.Fatal("Expected cache to be empty but it's not.")
	}
}
