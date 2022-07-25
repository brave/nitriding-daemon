package nitriding

import (
	"errors"
	"io"
	"syscall"
)

const (
	defaultFdCur     = 65536
	defaultFdMax     = 65536
	errTooMuchToRead = "reached read limit"
)

// limitReader behaves like a Reader but it returns errTooMuchToRead if the
// read limit was met or exceeded.
type limitReader struct {
	io.Reader
	Limit int
}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.Limit <= 0 {
		return 0, errors.New(errTooMuchToRead)
	}
	if len(p) > l.Limit {
		p = p[0:l.Limit]
	}
	n, err := l.Reader.Read(p)
	l.Limit -= n
	return n, err
}

func newLimitReader(r io.Reader, limit int) *limitReader {
	return &limitReader{
		Reader: r,
		Limit:  limit,
	}
}

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
