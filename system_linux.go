package nitriding

import (
	"fmt"
	"net"
	"os"

	"github.com/milosgajdos/tenus"
	"github.com/songgao/water"
)

var ourWaterParams = water.PlatformSpecificParams{
	Name:       ifaceTap,
	MultiQueue: true,
}

// configureLoIface assigns an IP address to the loopback interface.
func configureLoIface() error {
	l, err := tenus.NewLinkFrom(ifaceLo)
	if err != nil {
		return err
	}
	addr, network, err := net.ParseCIDR(addrLo)
	if err != nil {
		return err
	}
	if err = l.SetLinkIp(addr, network); err != nil {
		return err
	}
	return l.SetLinkUp()
}

// configureTapIface configures our TAP interface by assigning it a MAC
// address, IP address, and link MTU.  We could have used DHCP instead but that
// brings with it unnecessary complexity and attack surface.
func configureTapIface() error {
	l, err := tenus.NewLinkFrom(ifaceTap)
	if err != nil {
		return fmt.Errorf("failed to retrieve link: %w", err)
	}

	addr, network, err := net.ParseCIDR(addrTap)
	if err != nil {
		return fmt.Errorf("failed to parse CIDR: %w", err)
	}
	if err = l.SetLinkIp(addr, network); err != nil {
		return fmt.Errorf("failed to set link address: %w", err)
	}

	if err := l.SetLinkMTU(1500); err != nil {
		return fmt.Errorf("failed to set link MTU: %w", err)
	}

	if err := l.SetLinkMacAddress(mac); err != nil {
		return fmt.Errorf("failed to set MAC address: %w", err)
	}

	if err := l.SetLinkUp(); err != nil {
		return fmt.Errorf("failed to bring up link: %w", err)
	}

	gw := net.ParseIP(defaultGw)
	if err := l.SetLinkDefaultGw(&gw); err != nil {
		return fmt.Errorf("failed to set default gateway: %w", err)
	}

	return nil
}

// writeResolvconf creates our resolv.conf and adds a nameserver.
func writeResolvconf() error {
	// A Nitro Enclave's /etc/resolv.conf is a symlink to
	// /run/resolvconf/resolv.conf.  As of 2022-11-21, the /run/ directory
	// exists but not its resolvconf/ subdirectory.
	dir := "/run/resolvconf/"
	file := dir + "resolv.conf"

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}

	// Our default gateway -- gvproxy -- also operates a DNS resolver.
	c := fmt.Sprintf("nameserver %s\n", defaultGw)
	if err := os.WriteFile(file, []byte(c), 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}
