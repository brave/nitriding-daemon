package nitriding

import (
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
