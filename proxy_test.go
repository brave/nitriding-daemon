package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
)

func send(t *testing.T, sizeBuf, expectedBytes []byte, expectedErr error) {
	t.Helper()

	var err error
	var wg sync.WaitGroup
	wg.Add(1)
	errCh := make(chan error)
	go func() {
		err = <-errCh
		wg.Done()
	}()

	out := &bytes.Buffer{}
	in := bytes.NewBuffer(append(sizeBuf, expectedBytes...))
	tx(in, out, errCh)

	wg.Wait()
	if !errors.Is(err, expectedErr) {
		t.Fatalf("Expected error %v but got %v.", expectedErr, err)
	}

	actualBytes := out.Bytes()
	if !bytes.Equal(actualBytes, expectedBytes) {
		t.Fatalf("Expected to read bytes\n%v\nbut got\n%v", expectedBytes, actualBytes)
	}
}

func receive(t *testing.T, b []byte, expectedErr error) {
	t.Helper()

	var err error
	var wg sync.WaitGroup
	wg.Add(1)
	errCh := make(chan error)
	go func() {
		err = <-errCh
		wg.Done()
	}()

	expectedBytes := make([]byte, len(b)+frameSizeLen)
	binary.LittleEndian.PutUint16(expectedBytes[:frameSizeLen], uint16(len(b)))
	copy(expectedBytes[frameSizeLen:], b)

	out := &bytes.Buffer{}
	rx(out, bytes.NewBuffer(b), errCh)

	wg.Wait()
	if !errors.Is(err, expectedErr) {
		t.Fatalf("Expected error %v but got %v.", expectedErr, err)
	}

	actualBytes := out.Bytes()
	if !bytes.Equal(actualBytes, expectedBytes) {
		t.Fatalf("Expected to read bytes\n%v\nbut got\n%v", expectedBytes, actualBytes)
	}
}

func TestTx(t *testing.T) {
	expected := "foobar"
	frameSize := make([]byte, frameSizeLen)

	binary.LittleEndian.PutUint16(frameSize, uint16(len(expected)))
	send(t, frameSize, []byte(expected), io.EOF)
}

func TestRx(t *testing.T) {
	expected := "foobar"
	receive(t, []byte(expected), io.EOF)
}
