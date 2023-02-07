package nitriding

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"syscall"
	"testing"
	"time"
)

// signalReady signals to the enclave-internal Web server that we're ready,
// instructing it to spin up its Internet-facing Web server.
func signalReady(t *testing.T, e *Enclave) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, pathReady, nil)
	e.privSrv.Handler.ServeHTTP(rec, req)
	expect(t, rec.Result(), http.StatusOK, "")
	// There's no straightforward way to register a callback for when a Web
	// server has started because ListenAndServeTLS blocks for as long as the
	// server is alive.  Let's wait briefly to give the Web server enough time
	// to start.  An ugly test is better than no test.
	time.Sleep(100 * time.Millisecond)
}

func TestSyncHandler(t *testing.T) {
	e := createEnclave(&defaultCfg)
	h := reqSyncHandler(e)
	rec := httptest.NewRecorder()

	req, err := http.NewRequest(http.MethodGet, pathSync, nil)
	if err != nil {
		t.Fatalf("Failed to create HTTP request: %v", err)
	}
	h(rec, req)

	expect(t, rec.Result(), http.StatusBadRequest, errNoAddr.Error())
}

func TestStateHandlers(t *testing.T) {
	expected := []byte{1, 2, 3, 4, 5} // The key material that we're setting and retrieving.
	e := createEnclave(&defaultCfg)
	setHandler := putStateHandler(e)
	getHandler := getStateHandler(e)
	rec := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodPut, pathState, bytes.NewReader(expected))
	if err != nil {
		t.Fatalf("Failed to create HTTP request: %v", err)
	}

	setHandler(rec, req)
	resp := rec.Result()

	// As long as we don't hit our (generous) upload limit, we always expect an
	// HTTP 200 response.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected HTTP status code %d but got %d.", http.StatusOK, resp.StatusCode)
	}

	// Now retrieve the state and make sure that it's what we sent earlier.
	req, err = http.NewRequest(http.MethodGet, pathState, nil)
	if err != nil {
		t.Fatalf("Failed to create HTTP request: %v", err)
	}
	rec = httptest.NewRecorder()
	getHandler(rec, req)
	resp = rec.Result()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected HTTP status code %d but got %d.", http.StatusOK, resp.StatusCode)
	}

	retrieved, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read HTTP response body: %v", err)
	}
	if !bytes.Equal(expected, retrieved) {
		t.Fatalf("Expected state %q but got %q.", expected, retrieved)
	}
}

func TestProxyHandler(t *testing.T) {
	appPage := "foobar"

	// Nitring acts as a reverse proxy to this Web server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, appPage)
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	c := defaultCfg
	c.AppWebSrv = u
	e, err := NewEnclave(&c)
	if err != nil {
		t.Fatal(err)
	}
	e.revProxy = httputil.NewSingleHostReverseProxy(u)
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	defer e.Stop() //nolint:errcheck
	signalReady(t, e)

	// Skip certificate validation because we are using a self-signed
	// certificate in this test.
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	nitridingSrv := "https://127.0.0.1" + e.pubSrv.Addr

	// Request the enclave's index page.  Nitriding is going to return it.
	resp, err := http.Get(nitridingSrv + pathRoot)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, resp, http.StatusOK, indexPage)

	// Request a random page.  Nitriding is going to forwrad the request to our
	// test Web server.
	resp, err = http.Get(nitridingSrv + "/foo/bar")
	if err != nil {
		t.Fatal(err)
	}
	expect(t, resp, http.StatusOK, appPage)
}

func TestHashHandler(t *testing.T) {
	e := createEnclave(&defaultCfg)
	h := hashHandler(e)
	validHash := [sha256.Size]byte{}
	validHashB64 := base64.StdEncoding.EncodeToString(validHash[:])

	// Send invalid Base64.
	req, _ := http.NewRequest(http.MethodPost, pathHash, bytes.NewBufferString("foo"))
	rec := httptest.NewRecorder()
	h(rec, req)
	expect(t, rec.Result(), http.StatusBadRequest, errNoBase64.Error())

	// Send invalid hash size.
	req.Body = io.NopCloser(bytes.NewBufferString("AAAAAAAAAAAAAA=="))
	rec = httptest.NewRecorder()
	h(rec, req)
	expect(t, rec.Result(), http.StatusBadRequest, errHashWrongSize.Error())

	// Send too much data.
	req.Body = io.NopCloser(bytes.NewBufferString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))
	rec = httptest.NewRecorder()
	h(rec, req)
	expect(t, rec.Result(), http.StatusBadRequest, errTooMuchToRead.Error())

	// Finally, send a valid, Base64-encoded SHA-256 hash.
	req.Body = io.NopCloser(bytes.NewBufferString(validHashB64))
	rec = httptest.NewRecorder()
	h(rec, req)
	expect(t, rec.Result(), http.StatusOK, "")

	// Same as above but with an additional \n.
	req.Body = io.NopCloser(bytes.NewBufferString(validHashB64 + "\n"))
	rec = httptest.NewRecorder()
	h(rec, req)
	expect(t, rec.Result(), http.StatusOK, "")

	// Make sure that our hash was set correctly.
	if e.hashes.appKeyHash != validHash {
		t.Fatalf("Application key hash (%x) not as expected (%x).", e.hashes.appKeyHash, validHash)
	}
}

func TestReadiness(t *testing.T) {
	cfg := defaultCfg
	cfg.WaitForApp = false
	e := createEnclave(&cfg)
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	defer e.Stop() //nolint:errcheck

	nitridingSrv := fmt.Sprintf("https://127.0.0.1:%d", e.cfg.ExtPort)
	u := nitridingSrv + pathRoot
	// Make sure that the Internet-facing Web server is already running because
	// we didn't ask nitriding to wait for the application.  The Web server may
	// not be running by the time we test it, so we back off a few times, to
	// give the Web server time to start.
	func(t *testing.T, u string) {
		for i := 0; i < 100; i += 10 {
			resp, err := http.Get(u)
			// The server probably isn't ready yet.  Sleep briefly.
			if errors.Is(err, syscall.ECONNREFUSED) {
				time.Sleep(time.Millisecond * time.Duration(i))
				continue
			}
			if err != nil {
				t.Fatalf("Expected no error but got %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("Expected status code %d but got %d.",
					http.StatusOK, resp.StatusCode)
			}
			return
		}
		t.Fatal("Unable to talk to Internet-facing Web server.")
	}(t, u)
}

func TestReadyHandler(t *testing.T) {
	cfg := defaultCfg
	cfg.WaitForApp = true
	e := createEnclave(&cfg)
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	defer e.Stop() //nolint:errcheck

	// Check if the Internet-facing Web server is running.
	nitridingSrv := fmt.Sprintf("https://127.0.0.1:%d", e.cfg.ExtPort)
	_, err := http.Get(nitridingSrv + pathRoot)
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatal("Expected 'connection refused'.")
	}
	signalReady(t, e)

	// Check again.  It should be running this time.
	resp, err := http.Get(nitridingSrv + pathRoot)
	if err != nil {
		t.Fatalf("Expected no error but got %v.", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code %d but got %d.", http.StatusOK, resp.StatusCode)
	}
}
