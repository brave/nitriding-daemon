package main

import (
	"log"
	"net/http"
	"os/exec"
	"time"
)

const (
	appPath = "/tmp/enclave-application" // Where to store the enclave application.
)

// appRetriever implements an interface that retrieves an enclave application at
// runtime.  This allows us to retrieve the application via various mechanisms,
// like a Web API or a Docker registry.
type appRetriever interface {
	retrieve(*http.Server, chan []byte) error
}

// appLoader implements a mechanism that can retrieve and execute an enclave
// application at runtime.
type appLoader struct {
	srv       *http.Server
	log       transparencyLog
	app       chan []byte
	appExited chan struct{}
	appRetriever
}

// newAppLoader returns a new appLoader object.
func newAppLoader(srv *http.Server, r appRetriever) *appLoader {
	return &appLoader{
		srv:          srv,
		log:          new(memLog),
		app:          make(chan []byte),
		appExited:    make(chan struct{}),
		appRetriever: r,
	}
}

// runCmd runs the enclave application.  The function blocks for as long as the
// application is running.
func (l *appLoader) runCmd() {
	cmd := exec.Command(appPath)
	err := cmd.Run()
	elog.Printf("Enclave application exited: %v", err)
	l.appExited <- struct{}{}
}

// appendToLog appends the given digest to our append-only log.
func (l *appLoader) appendToLog(app []byte) {
	l.log.append(newSHA256LogRecord(app))
}

// start executes the enclave application.
func (l *appLoader) start(stop chan struct{}) {
	var (
		err error
	)
	elog.Println("Starting app loader event loop.")
	defer elog.Println("Stopping app loader event loop.")

	go l.retrieve(l.srv, l.app)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-l.appExited:
				time.Sleep(time.Second)
				elog.Println(l.log)
				go l.runCmd()

			case app := <-l.app:
				if err = writeToDisk(app); err != nil {
					log.Fatalf("Error writing enclave application to disk: %v", err)
				}
				l.appendToLog(app)
				go l.runCmd()
			}
		}
	}()
}
