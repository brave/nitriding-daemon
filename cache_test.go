package nitriding

import (
	"testing"
	"time"
)

func TestCache(t *testing.T) {
	c := newCache(time.Millisecond * 50)
	elem := "foo"

	c.Add(elem)
	if !c.Exists(elem) {
		t.Errorf("Expected element not found in cache.")
	}

	// Wait until the element expired.
	time.Sleep(time.Millisecond * 100)
	if c.Exists(elem) {
		t.Errorf("Element in cache despite being expired.")
	}

	// Now ask for a non-existing item.
	if c.Exists("bar") {
		t.Errorf("Non-existing element is supposed to exist.")
	}
}
