package main

import "testing"

func TestSliceToNonce(t *testing.T) {
	var err error

	_, err = sliceToNonce([]byte("foo"))
	assertEqual(t, err, errBadSliceLen)

	_, err = sliceToNonce(make([]byte, nonceLen))
	assertEqual(t, err, nil)
}
