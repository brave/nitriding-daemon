package randseed

import (
	"errors"
	"os"
)

const nsmDevPath = "/dev/nsm"

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
