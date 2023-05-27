package main

import (
	"bytes"
	"errors"
	"io"
	"syscall"
	"testing"
)

func checkFdLimit(t *testing.T, cur, max uint64) {
	var rLimit = new(syscall.Rlimit)
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, rLimit); err != nil {
		t.Fatalf("Failed to get file descriptor limit: %s", err)
	}
	if rLimit.Cur != cur || rLimit.Max != max {
		t.Fatal("Got unexpected file descriptor limits.")
	}
}

func TestLimitReaderEOF(t *testing.T) {
	bufContent := []byte("foo")
	readBuf := bytes.NewReader(bufContent)
	writeBuf := make([]byte, len(bufContent)*2)

	lreader := newLimitReader(readBuf, len(bufContent))
	// The first Read is going to drain the limitReader's buffer but won't
	// result in an EOF yet.
	n, err := lreader.Read(writeBuf)
	if n != len(bufContent) {
		t.Fatalf("Expected to read %d bytes but got %d.", len(bufContent), n)
	}
	if err != nil {
		t.Fatalf("Expected nil but got %v.", err)
	}

	// The next and final Read is going to read 0 bytes (because the buffer is
	// empty) and return EOF.
	n, err = lreader.Read(writeBuf)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Expected EOF but got %v.", err)
	}
	if n != 0 {
		t.Fatalf("Expected to read 0 bytes but got %d.", n)
	}
	if !bytes.Equal(bufContent, writeBuf[:len(bufContent)]) {
		t.Fatalf("Expected to read %s but got %s.", bufContent, writeBuf)
	}
}

func TestLimitReader(t *testing.T) {
	bufContent := []byte("foobar")

	// Hand the reader too much.
	buf := bytes.NewReader(bufContent)
	_, err := io.ReadAll(newLimitReader(buf, len(bufContent)-1))
	if !errors.Is(err, errTooMuchToRead) {
		t.Fatalf("Expected error %q but got %v.", errTooMuchToRead, err)
	}

	// Hand the reader the maximum allowable amount.
	buf = bytes.NewReader(bufContent)
	ret, err := io.ReadAll(newLimitReader(buf, len(bufContent)))
	if err != nil {
		t.Fatalf("Failed to read maximum allowable amount: %s", err)
	}
	if !bytes.Equal(ret, bufContent) {
		t.Fatalf("Expected to read %q into buffer but got %q.", bufContent, ret)
	}
}

func TestSetFdLimit(t *testing.T) {
	var err error

	// Check if default values are set correctly.
	if err = setFdLimit(0, 0); err != nil {
		t.Fatalf("Failed to set file descriptor limit: %s", err)
	}
	checkFdLimit(t, defaultFdCur, defaultFdMax)

	// Check if custom values are set correctly.
	if err = setFdLimit(defaultFdCur-1, defaultFdMax-1); err != nil {
		t.Fatalf("Failed to set file descriptor limit: %s", err)
	}
	checkFdLimit(t, defaultFdCur-1, defaultFdMax-1)
}
