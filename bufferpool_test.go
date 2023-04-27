package nitriding

import "testing"

func TestBufPool(t *testing.T) {
	p := newBufPool()
	s1 := p.Get()
	p.Put(s1)
	s2 := p.Get()

	if len(s1) != len(s2) {
		t.Fatalf("Byte slices have different lengths (%d vs %d).", len(s1), len(s2))
	}
}
