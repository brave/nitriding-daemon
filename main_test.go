package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSpawnAppProcess(t *testing.T) {
	expected := []string{"1", "2", "3"}
	output := []string{}
	f := func(s string) {
		output = append(output, strings.TrimSpace(s))
	}
	dummy := func(string) {}

	runAppCommand("seq 1 3", f, dummy)
	if len(output) != len(expected) {
		t.Fatalf("Expected slice length %d but got %d.", len(expected), len(output))
	}

	for i := range output {
		if output[i] != expected[i] {
			t.Fatalf("Expected element at index %d to be %s but got %s.", i, expected[i], output[i])
		}
	}
}

// TestSpawnAppProcessWaitsForOutput verifies that runAppCommand does not return
// until every line written by the application has been delivered to the
// callback. Regression test for issue #39.
//
// The test exercises the race between cmd.Wait closing the read end of the
// stdout/stderr pipes and the forwarder goroutines iterating through lines
// already buffered by bufio.Scanner. Once the process exits, cmd.Wait can
// return quickly while the goroutines are still draining buffered lines into
// the (intentionally slow) callback. Without a sync.WaitGroup gating the
// return on the goroutines, runAppCommand returns prematurely.
func TestSpawnAppProcessWaitsForOutput(t *testing.T) {
	const stdoutLines = 50
	const stderrLines = 50
	const perLineDelay = 5 * time.Millisecond

	script := filepath.Join(t.TempDir(), "burst.sh")
	var body strings.Builder
	body.WriteString("#!/bin/sh\n")
	for range stdoutLines {
		body.WriteString("echo out\n")
	}
	for range stderrLines {
		body.WriteString("echo err >&2\n")
	}
	if err := os.WriteFile(script, []byte(body.String()), 0o755); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}

	var stdout, stderr atomic.Int32
	slowStdout := func(string) {
		time.Sleep(perLineDelay)
		stdout.Add(1)
	}
	slowStderr := func(string) {
		time.Sleep(perLineDelay)
		stderr.Add(1)
	}

	runAppCommand(script, slowStdout, slowStderr)

	if got := stdout.Load(); got != stdoutLines {
		t.Fatalf("runAppCommand returned with stdout output still pending: got %d/%d lines", got, stdoutLines)
	}
	if got := stderr.Load(); got != stderrLines {
		t.Fatalf("runAppCommand returned with stderr output still pending: got %d/%d lines", got, stderrLines)
	}
}
