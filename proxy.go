package main

// Code mostly taken from:
// https://github.com/containers/gvisor-tap-vsock/blob/main/cmd/vm/main_linux.go

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/transport"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

var (
	frameLen     = 0xffff
	frameSizeLen = 2
)

// runNetworking calls the function that sets up our networking environment.
// If anything fails, we try again after a brief wait period.
func runNetworking(c *Config, stop chan struct{}) {
	var err error
	for {
		if err = setupNetworking(c, stop); err == nil {
			return
		}
		elog.Printf("TAP tunnel to EC2 host failed: %v.  Restarting.", err)
		time.Sleep(time.Second)
	}
}

// setupNetworking sets up the enclave's networking environment.  In
// particular, this function:
//
//  1. Creates a TAP device.
//  2. Set up networking links.
//  3. Establish a connection with the proxy running on the host.
//  4. Spawn goroutines to forward traffic between the TAP device and the proxy
//     running on the host.
	elog.Println("Setting up networking between host and enclave.")
	defer elog.Println("Tearing down networking between host and enclave.")
func setupNetworking(c *Config, stop chan struct{}) error {

	// Establish connection with the proxy running on the EC2 host.
	endpoint := fmt.Sprintf("vsock://%d:%d/connect", parentCID, c.HostProxyPort)
	conn, path, err := transport.Dial(endpoint)
	if err != nil {
		return fmt.Errorf("failed to connect to host: %w", err)
	}
	defer conn.Close()
	elog.Println("Established connection with EC2 host.")

	req, err := http.NewRequest(http.MethodPost, path, nil)
	if err != nil {
		return fmt.Errorf("failed to create POST request: %w", err)
	}
	if err := req.Write(conn); err != nil {
		return fmt.Errorf("failed to send POST request to host: %w", err)
	}
	elog.Println("Sent HTTP request to EC2 host.")

	// Create a TAP interface.
	tap, err := water.New(water.Config{
		DeviceType:             water.TAP,
		PlatformSpecificParams: ourWaterParams,
	})
	if err != nil {
		return fmt.Errorf("failed to create tap device: %w", err)
	}
	defer tap.Close()
	elog.Println("Created TAP device.")

	// Configure IP address, MAC address, MTU, default gateway, and DNS.
	if err = configureTapIface(); err != nil {
		return fmt.Errorf("failed to configure tap interface: %w", err)
	}
	if err = writeResolvconf(); err != nil {
		return fmt.Errorf("failed to create resolv.conf: %w", err)
	}

	// Set up networking links.
	if err := linkUp(); err != nil {
		return fmt.Errorf("failed to set MAC address: %w", err)
	}
	elog.Println("Created networking link.")

	// Spawn goroutines that forward traffic.
	errCh := make(chan error, 1)
	go tx(conn, tap, errCh)
	go rx(conn, tap, errCh)
	elog.Println("Started goroutines to forward traffic.")
	select {
	case err := <-errCh:
		return err
	case <-stop:
		elog.Printf("Shutting down networking.")
		return nil
	}
}

func linkUp() error {
	link, err := netlink.LinkByName(ifaceTap)
	if err != nil {
		return err
	}
	if mac == "" {
		return netlink.LinkSetUp(link)
	}
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetHardwareAddr(link, hw); err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func rx(conn io.Writer, tap io.Reader, errCh chan error) {
	elog.Println("Waiting for frames from enclave application.")
	buf := make([]byte, frameSizeLen+frameLen) // Two bytes for the frame length plus the frame itself

	for {
		n, err := tap.Read([]byte(buf[frameSizeLen:]))
		if err != nil {
			errCh <- fmt.Errorf("failed to read payload from enclave application: %w", err)
			return
		}

		binary.LittleEndian.PutUint16(buf[:frameSizeLen], uint16(n))
		m, err := conn.Write(buf[:frameSizeLen+n])
		if err != nil {
			errCh <- fmt.Errorf("failed to write payload to host: %w", err)
			return
		}
		m = m - frameSizeLen
		if m != n {
			errCh <- fmt.Errorf("wrote %d instead of %d bytes to host", m, n)
			return
		}
	}
}

func tx(conn io.Reader, tap io.Writer, errCh chan error) {
	elog.Println("Waiting for frames from host.")
	buf := make([]byte, frameSizeLen+frameLen) // Two bytes for the frame length plus the frame itself

	for {
		n, err := io.ReadFull(conn, buf[:frameSizeLen])
		if err != nil {
			errCh <- fmt.Errorf("failed to read length from host: %w", err)
			return
		}
		if n != frameSizeLen {
			errCh <- fmt.Errorf("received unexpected length %d", n)
			return
		}
		size := int(binary.LittleEndian.Uint16(buf[:frameSizeLen]))

		n, err = io.ReadFull(conn, buf[frameSizeLen:size+frameSizeLen])
		if err != nil {
			errCh <- fmt.Errorf("failed to read payload from host: %w", err)
			return
		}
		if n == 0 || n != size {
			errCh <- fmt.Errorf("expected payload of size %d but got %d", size, n)
			return
		}

		m, err := tap.Write(buf[frameSizeLen : n+frameSizeLen])
		if err != nil {
			errCh <- fmt.Errorf("failed to write payload to enclave application: %w", err)
			return
		}
		if m != n {
			errCh <- fmt.Errorf("wrote %d instead of %d bytes to host", m, n)
			return
		}
	}
}
