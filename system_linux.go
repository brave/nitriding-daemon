package nitriding

import (
	"net"

	"github.com/milosgajdos/tenus"
)

// assignAddrToIface assigns the given IP address (in CIDR notation) to the
// given network interface.
func assignAddrToIface(addrStr, iface string) error {
	l, err := tenus.NewLinkFrom(iface)
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
