package main

import (
	"os"
	"testing"
)

func TestSliceToNonce(t *testing.T) {
	var err error

	_, err = sliceToNonce([]byte("foo"))
	assertEqual(t, err, errBadSliceLen)

	_, err = sliceToNonce(make([]byte, nonceLen))
	assertEqual(t, err, nil)
}

func TestWriteToDisk(t *testing.T) {
	assertEqual(t, writeToDisk([]byte("foo")), nil)
	defer os.Remove(appPath)
}
