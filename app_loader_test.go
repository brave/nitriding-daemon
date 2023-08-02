package main

import (
	"net/http"
	"testing"
)

type appRetrieverDummy struct{}

func (d *appRetrieverDummy) retrieve(srv *http.Server, appChan chan []byte) error {
	//var once sync.Once
	go func(appChan chan []byte) {
		// once.Do()
		// sync.Once()
		appChan <- []byte("") // Dummy application.
	}(appChan)
	return nil
}

func TestStartStop(t *testing.T) {
	var (
		loader = newAppLoader(nil, new(appRetrieverDummy))
		stop   = make(chan struct{})
	)
	defer close(stop)
	loader.start(stop)
}
