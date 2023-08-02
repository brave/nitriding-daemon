package main

import (
	"bytes"
	"testing"
)

func TestSHA256RecordCreation(t *testing.T) {
	var (
		r1 = newSHA256LogRecord([]byte("foo"))
		r2 = newSHA256LogRecord([]byte("foo"))
		r3 = newSHA256LogRecord([]byte("bar"))
	)

	// Check if the digests match.
	hasSameDigest := func(r1, r2 *logRecord) bool {
		if r1.digestType != r2.digestType {
			return false
		}
		if r1.digestSize != r2.digestSize {
			return false
		}
		return bytes.Equal(r1.digest, r2.digest)
	}
	assertEqual(t, hasSameDigest(r1, r2), true)
	assertEqual(t, hasSameDigest(r1, r3), false)
	assertEqual(t, hasSameDigest(r2, r3), false)

	// Check if the timestamps match.
	assertEqual(t, r1.time == r2.time, false)
	assertEqual(t, r1.time == r3.time, false)
	assertEqual(t, r2.time == r3.time, false)

	// Check if the string representations match.
	// We're not testing r1 against r2 because the result is not deterministic
	// due to time being part of the string representation.
	assertEqual(t, r1.String() == r3.String(), false)
	assertEqual(t, r2.String() == r3.String(), false)
}

func TestMemLog(t *testing.T) {
	var (
		m  = new(memLog)
		r1 = newSHA256LogRecord([]byte("foo"))
		r2 = newSHA256LogRecord([]byte("bar"))
	)

	// Check if appending works correctly.
	assertEqual(t, m.size(), 0)
	m.append(r1)
	assertEqual(t, m.size(), 1)
	m.append(r2)
	assertEqual(t, m.size(), 2)

	// Check that we get some sort of string representation.
	assertEqual(t, len(m.String()) > 0, true)
}
