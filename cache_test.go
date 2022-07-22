package nitriding

import (
	"fmt"
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

func TestCacheWithManyElems(t *testing.T) {
	c := newCache(time.Millisecond * 50)

	// Add 100 items.
	for i := 0; i < 100; i++ {
		c.Add(fmt.Sprintf("%d", i))
	}

	// Wait for those 100 items to expire.
	time.Sleep(time.Millisecond * 100)

	// Add another 100 items.
	for i := 100; i < 200; i++ {
		c.Add(fmt.Sprintf("%d", i))
	}

	// We now expect 100 items to remain in the cache.
	count := c.Count()
	if count != 100 {
		t.Fatalf("Expected 100 but got %d elems in cache.", count)
	}
}
