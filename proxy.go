package nitriding

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
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var (
	mtu = 4000
)

const (
	// mac indicates the MAC address of the enclave.
	mac = "5a:94:ef:e4:0c:ee"
)

// runNetworking calls the function that sets up our networking environment.
// If anything fails, we try again after a brief wait period.
func runNetworking(c *Config, stop chan bool) {
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
func setupNetworking(c *Config, stop chan bool) error {
	elog.Println("Setting up networking between host and enclave.")
	defer elog.Println("Tearing down networking between host and enclave.")

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
		DeviceType: water.TAP,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name:       ifaceTap,
			MultiQueue: true,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create tap device: %w", err)
	}
	defer tap.Close()
	elog.Println("Created TAP device.")

	// Assign an IP address to our freshly creates interface.
	if err = assignAddrToIface(addrTap, ifaceTap); err != nil {
		return fmt.Errorf("failed to assign tap address: %w", err)
	}

	// Set up networking links.
	if err := linkUp(); err != nil {
		return fmt.Errorf("failed to set MAC address: %w", err)
	}
	elog.Println("Created networking link.")

	// Spawn goroutines that forward traffic.
	errCh := make(chan error, 1)
	go tx(conn, tap, errCh, mtu)
	go rx(conn, tap, errCh, mtu)
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

func rx(conn net.Conn, tap *water.Interface, errCh chan error, mtu int) {
	elog.Println("Waiting for frames from enclave application.")
	var frame ethernet.Frame
	for {
		frame.Resize(mtu)
		n, err := tap.Read([]byte(frame))
		if err != nil {
			errCh <- fmt.Errorf("failed to read packet from TAP device: %w", err)
			return
		}
		frame = frame[:n]

		size := make([]byte, 2)
		binary.LittleEndian.PutUint16(size, uint16(n))

		if _, err := conn.Write(size); err != nil {
			errCh <- fmt.Errorf("failed to write frame size to connection: %w", err)
			return
		}
		if _, err := conn.Write(frame); err != nil {
			errCh <- fmt.Errorf("failed to write frame to connection: %w", err)
			return
		}
	}
}

func tx(conn net.Conn, tap *water.Interface, errCh chan error, mtu int) {
	elog.Println("Waiting for frames from host.")
	sizeBuf := make([]byte, 2)
	buf := make([]byte, mtu+header.EthernetMinimumSize)

	for {
		n, err := io.ReadFull(conn, sizeBuf)
		if err != nil {
			errCh <- fmt.Errorf("failed to read frame size from connection: %w", err)
			return
		}
		if n != 2 {
			errCh <- fmt.Errorf("received unexpected frame size %d", n)
			return
		}
		size := int(binary.LittleEndian.Uint16(sizeBuf[0:2]))

		n, err = io.ReadFull(conn, buf[:size])
		if err != nil {
			errCh <- fmt.Errorf("failed to read frame from connection: %w", err)
			return
		}
		if n == 0 || n != size {
			errCh <- fmt.Errorf("expected frame of size %d but got %d", size, n)
			return
		}

		if _, err := tap.Write(buf[:size]); err != nil {
			errCh <- fmt.Errorf("failed to write frame to TAP device: %w", err)
			return
		}
	}
}
