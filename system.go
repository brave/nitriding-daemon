package enclaveutils

import (
	"errors"
	"net"
	"os"

	"github.com/milosgajdos/tenus"
)

const (
	nsmDevPath = "/dev/nsm"
)

// assignLoAddr assigns an IP address to the loopback interface, which is
// necessary because Nitro enclaves don't do that out-of-the-box.  We need the
// loopback interface because we run a simple TCP proxy that listens on
// 127.0.0.1:1080 and converts AF_INET to AF_VSOCK.
func assignLoAddr() error {
	addrStr := "127.0.0.1/8"
	l, err := tenus.NewLinkFrom("lo")
	if err != nil {
		return err
	}
	addr, network, err := net.ParseCIDR(addrStr)
	if err != nil {
		return err
	}
	if err = l.SetLinkIp(addr, network); err != nil {
		return err
	}
	return l.SetLinkUp()
}

// InEnclave returns true if we are running in a Nitro enclave and false
// otherwise.  If something goes wrong during the check, an error is returned.
func InEnclave() (bool, error) {
	if _, err := os.Stat(nsmDevPath); err == nil {
		return true, nil
	} else if errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else {
		return false, err
	}
}
