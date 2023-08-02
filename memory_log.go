package main

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// transparencyLog implements an interface for an append-only data structure
// that serves as a transparency log for enclave image IDs.
type transparencyLog interface {
	append(*logRecord) error
	String() string // human-readable representation
}

// logRecord represents a single record in our transparency log.
type logRecord struct {
	digestType byte
	digestSize byte
	digest     []byte
	time       time.Time
}

// newSHA256LogRecord creates a new logRecord that uses SHA-2-256 for the given
// byte blob.
func newSHA256LogRecord(blob []byte) *logRecord {
	digest := sha256.Sum256(blob)
	return &logRecord{
		digestType: 0x12, // SHA-2-256.
		digestSize: 0x20, // 32 bytes, in the "variable integer" multiformat.
		digest:     digest[:],
		time:       time.Now(),
	}
}

// String returns a string representation of the log record.
func (r *logRecord) String() string {
	return fmt.Sprintf("%s: %x (type=%x)\n", r.time.Format(time.RFC3339), r.digest, r.digestType)
}

// memLog implements a transparencyLog in memory.
type memLog struct {
	sync.Mutex
	log []*logRecord
}

// append appends the given logRecord to the memory log.
func (m *memLog) append(r *logRecord) error {
	m.Lock()
	defer m.Unlock()

	m.log = append(m.log, r)
	elog.Printf("Appended %s to transparency log of new size %d.", r, len(m.log))
	return nil
}

// size returns the memory log's size.
func (m *memLog) size() int {
	m.Lock()
	defer m.Unlock()

	return len(m.log)
}

// String returns a string representation of the memory log.
func (m *memLog) String() string {
	m.Lock()
	defer m.Unlock()

	var s string
	for _, r := range m.log {
		s += r.String()
	}
	return s
}
