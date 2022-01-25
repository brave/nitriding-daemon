package randseed

import (
	"errors"
	"log"
	"os"
	"unsafe"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"

	"golang.org/x/sys/unix"
)

const (
	entropySeedDevice = "/dev/random"
	entropySeedSize   = 2048
)

// init obtains cryptographically secure random bytes from the Nitro Secure
// Module (NSM) and uses them to initialize the system's random number
// generator.  If we don't do that, our system is going to start with no
// entropy, which means that calls to /dev/(u)random will block.
func init() {
	// Abort if there's no /dev/nsm; e.g., when running unit tests outside of a
	// Nitro Enclave.
	if _, err := os.Stat("/dev/nsm"); errors.Is(err, os.ErrNotExist) {
		return
	}

	s, err := nsm.OpenDefaultSession()
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = s.Close()
	}()

	fd, err := os.OpenFile(entropySeedDevice, os.O_WRONLY, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err = fd.Close(); err != nil {
			log.Printf("Failed to close %q: %s", entropySeedDevice, err)
		}
	}()

	var written int
	for totalWritten := 0; totalWritten < entropySeedSize; {
		// We ignore the error because of a bug that will return an error
		// despite having obtained an attestation document:
		// https://github.com/hf/nsm/issues/2
		res, _ := s.Send(&request.GetRandom{})
		if res.Error != "" {
			log.Fatal(res.Error)
		}
		if res.GetRandom == nil {
			log.Fatal("no GetRandom part in NSM's response")
		}
		if len(res.GetRandom.Random) == 0 {
			log.Fatal("got no random bytes from NSM")
		}

		// Write NSM-provided random bytes to the system's entropy pool to seed
		// it.
		if written, err = fd.Write(res.GetRandom.Random); err != nil {
			log.Fatal(err)
		}
		totalWritten += written

		// Tell the system to update its entropy count.
		if _, _, errno := unix.Syscall(
			unix.SYS_IOCTL,
			uintptr(fd.Fd()),
			uintptr(unix.RNDADDTOENTCNT),
			uintptr(unsafe.Pointer(&written)),
		); errno != 0 {
			log.Printf("Failed to update system's entropy count: %s", errno)
		}
	}

	log.Println("Initialized the system's entropy pool.")
}
