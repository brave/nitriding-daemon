package main

import (
	"strings"
	"testing"
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
