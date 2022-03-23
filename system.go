package enclaveutils

import (
	"net"
	"syscall"

	"github.com/milosgajdos/tenus"
)

const (
	defaultFdCur = 65536
	defaultFdMax = 65536
)

// setFdLimit sets the process's file descriptor limit to the given soft (cur)
// and hard (max) cap.  If either of the two given values is 0, we use our
// default value instead.
func setFdLimit(cur, max uint64) error {
	var rLimit = new(syscall.Rlimit)

	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, rLimit); err != nil {
		return err
	}
	elog.Printf("Original file descriptor limit for cur=%d; max=%d.", rLimit.Cur, rLimit.Max)

	rLimit.Cur, rLimit.Max = cur, max
	if cur == 0 {
		rLimit.Cur = defaultFdCur
	}
	if max == 0 {
		rLimit.Max = defaultFdMax
	}

	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, rLimit); err != nil {
		return err
	}

	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, rLimit); err != nil {
		return err
	}
	elog.Printf("Modified file descriptor limit for cur=%d; max=%d.", rLimit.Cur, rLimit.Max)

	return nil
}

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
