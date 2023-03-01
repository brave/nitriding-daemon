package nitriding

import "github.com/songgao/water"

var ourWaterParams = water.PlatformSpecificParams{Name: ifaceTap}

// Nitriding does not run on macOS but by implementing the following dummy
// functions, we can at least get it to compile.
func configureLoIface() error  { return nil }
func configureTapIface() error { return nil }
func writeResolvconf() error   { return nil }
