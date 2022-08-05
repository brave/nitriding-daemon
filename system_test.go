package nitriding

import (
	"bytes"
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

func TestLimitReader(t *testing.T) {
	bufContent := []byte("foobar")

	// Hand the reader too much.
	buf := bytes.NewReader(bufContent)
	if _, err := io.ReadAll(newLimitReader(buf, len(bufContent)-1)); err == nil {
		t.Fatalf("Expected error %q but got none.", errTooMuchToRead)
	}

	// Hand the reader the maximum allowable amount.
	buf = bytes.NewReader(bufContent)
	ret, err := io.ReadAll(newLimitReader(buf, len(bufContent)))
	if err != nil {
		t.Fatal(err)
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
