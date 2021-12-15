package enclaveutils

import (
	"errors"
	"net"
	"os"
	"unsafe"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/milosgajdos/tenus"
	"golang.org/x/sys/unix"
)

const (
	seedDevice = "/dev/random"
	seedSize   = 2048
)

// seedEntropyPool obtains cryptographically secure random bytes from the
// Nitro's NSM and uses them to initialize seedDevice with seedSize bytes.  If
// we don't do that, our system is going to start with no entropy, which means
// that calls to /dev/(u)random will block.
func seedEntropyPool() error {
	s, err := nsm.OpenDefaultSession()
	if err != nil {
		return err
	}
	defer func() {
		_ = s.Close()
	}()

	fd, err := os.OpenFile(seedDevice, os.O_WRONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer func() {
		_ = fd.Close()
	}()

	var written int
	for totalWritten := 0; totalWritten < seedSize; {
		// We ignore the error because of a bug that will return an error
		// despite having obtained an attestation document:
		// https://github.com/hf/nsm/issues/2
		res, _ := s.Send(&request.GetRandom{})
		if res.Error != "" {
			return errors.New(string(res.Error))
		}
		if res.GetRandom == nil {
			return errors.New("no GetRandom part in NSM's response")
		}
		if len(res.GetRandom.Random) == 0 {
			return errors.New("got no random bytes from NSM")
		}

		// Write NSM-provided random bytes to the system's entropy pool to seed
		// it.
		if written, err = fd.Write(res.GetRandom.Random); err != nil {
			return err
		}
		totalWritten += written

		// Tell the system to update its entropy count.
		if _, _, errno := unix.Syscall(
			unix.SYS_IOCTL,
			uintptr(fd.Fd()),
			uintptr(unix.RNDADDTOENTCNT),
			uintptr(unsafe.Pointer(&written)),
		); errno != 0 {
			return errors.New("failed to update the system's entropy count")
		}
	}
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
	if err = l.SetLinkUp(); err != nil {
		return err
	}
	return nil
}
