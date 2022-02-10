package enclaveutils

// This file implements a TCP proxy that translates from AF_INET to AF_VSOCK.
// That allows enclave-internal code to establish TCP connections to
// enclave-external services (e.g., a SOCKS proxy) without having to deal with
// AF_VSOCK.

import (
	"net"

	"github.com/mdlayher/vsock"
)

// According to AWS docs, the CID (anaelogous to an IP address) of the
// parent instance is always 3:
// https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html
const parentCID = 3

// VProxy implements a TCP proxy that translates from AF_INET (to the left) to
// AF_VSOCK (to the right).
type VProxy struct {
	raddr *vsock.Addr
	laddr *net.TCPAddr
}

// Start starts the proxy.  Once the proxy is up and running, it signals its
// readiness over the given channel.
func (p *VProxy) Start(done chan bool) {
	// Bind to TCP address.
	ln, err := net.Listen("tcp", p.laddr.String())
	if err != nil {
		elog.Fatalf("Failed to bind to %s: %s", p.laddr.String(), err)
	}
	done <- true // Signal to caller that we're ready to accept connections.

	for {

		elog.Println("Waiting for new outgoing TCP connection.")
		lconn, err := ln.Accept()
		if err != nil {
			elog.Printf("Failed to accept proxy connection: %s", err)
			continue
		}
		elog.Println("Accepted new outgoing TCP connection.")

		// Establish connection with SOCKS proxy via our vsock interface.
		rconn, err := vsock.Dial(p.raddr.ContextID, p.raddr.Port)
		if err != nil {
			elog.Printf("Failed to establish connection to SOCKS proxy: %s", err)
			continue
		}
		elog.Println("Established connection with SOCKS proxy over vsock.")

		// Now pipe data from left to right and vice versa.
		go p.pipe(lconn, rconn)
		go p.pipe(rconn, lconn)
	}
}

// pipe forwards packets from src to dst and from dst to src.
func (p *VProxy) pipe(src, dst net.Conn) {
	defer func() {
		if err := src.Close(); err != nil {
			elog.Printf("Failed to close connection: %s", err)
		}
	}()
	buf := make([]byte, 0xffff)
	for {
		n, err := src.Read(buf)
		if err != nil {
			elog.Printf("Failed to read from src connection: %s", err)
			return
		}
		b := buf[:n]
		n, err = dst.Write(b)
		if err != nil {
			elog.Printf("Failed to write to dst connection: %s", err)
			return
		}
		if n != len(b) {
			elog.Printf("Only wrote %d out of %d bytes.", n, len(b))
			return
		}
	}
}

// NewVProxy returns a new vProxy instance.
func NewVProxy(bindAddr *net.TCPAddr, dstPort uint32) (*VProxy, error) {
	return &VProxy{
		raddr: &vsock.Addr{ContextID: parentCID, Port: dstPort},
		laddr: bindAddr,
	}, nil
}
