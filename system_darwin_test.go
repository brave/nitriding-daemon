package main

import "testing"

func TestNetworking(t *testing.T) {
	assertEqual(t, configureLoIface(), nil)
	assertEqual(t, configureTapIface(), nil)
	assertEqual(t, writeResolvconf(), nil)
}
