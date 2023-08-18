package main

import (
	"errors"
	"testing"

	"github.com/hf/nitrite"
)

func TestVerifyNitroAttstn(t *testing.T) {
	var n = newNitroAttester()
	_, err := n.verifyAttstn([]byte("foobar"), nonce{})
	assertEqual(t, errors.Is(err, nitrite.ErrBadCOSESign1Structure), true)
}

func TestCreateNitroAttstn(t *testing.T) {
	var n = newNitroAttester()
	_, err := n.createAttstn(nil)
	assertEqual(t, err != nil, true)
}
