package main

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

// makeRequestFor is a helper function that creates an HTTP request.
func makeRequestFor(srv *http.Server) func(method, path string, body io.Reader) *http.Response {
	return func(method, path string, body io.Reader) *http.Response {
		req := httptest.NewRequest(method, path, body)
		rec := httptest.NewRecorder()
		srv.Handler.ServeHTTP(rec, req)
		return rec.Result()
	}
}

// newResp is a helper function that creates an HTTP response.
func newResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
}

// assertResponse ensures that the two given HTTP responses are (almost)
// identical.  We only check the HTTP status code and the response body.
func assertResponse(t *testing.T, actual, expected *http.Response) {
	t.Helper()

	if actual.StatusCode != expected.StatusCode {
		t.Fatalf("expected status code %d but got %d", expected.StatusCode, actual.StatusCode)
	}

	expectedBody, err := io.ReadAll(expected.Body)
	if err != nil {
		t.Fatalf("failed to read expected response body: %v", err)
	}
	actualBody, err := io.ReadAll(actual.Body)
	if err != nil {
		t.Fatalf("failed to read actual response body: %v", err)
	}

	if len(expectedBody) == 0 {
		return
	}
	// Remove the last byte of the actual body if it's a newline.
	if len(actualBody) > 0 && actualBody[len(actualBody)-1] == '\n' {
		actualBody = actualBody[:len(actualBody)-1]
	}
	if !bytes.Equal(expectedBody, actualBody) {
		t.Fatalf("expected HTTP body\n%q\nbut got\n%q", string(expectedBody), string(actualBody))
	}
}

func TestRootHandler(t *testing.T) {
	makeReq := makeRequestFor(createEnclave(&defaultCfg).pubSrv)

	assertResponse(t,
		makeReq(http.MethodGet, pathRoot, nil),
		newResp(http.StatusOK, formatIndexPage(defaultCfg.AppURL)),
	)
}

// signalReady signals to the enclave-internal Web server that we're ready,
// instructing it to spin up its Internet-facing Web server.
func signalReady(t *testing.T, e *Enclave) {
	t.Helper()
	makeReq := makeRequestFor(e.privSrv)

	assertResponse(t,
		makeReq(http.MethodGet, pathReady, nil),
		newResp(http.StatusOK, ""),
	)

	// There's no straightforward way to register a callback for when a Web
	// server has started because ListenAndServeTLS blocks for as long as the
	// server is alive.  Let's wait briefly to give the Web server enough time
	// to start.  An ugly test is better than no test.
	time.Sleep(100 * time.Millisecond)
}

func TestSyncHandler(t *testing.T) {
	makeReq := makeRequestFor(createEnclave(&defaultCfg).privSrv)

	assertResponse(t,
		makeReq(http.MethodGet, pathSync, nil),
		newResp(http.StatusBadRequest, errNoAddr.Error()),
	)

	assertResponse(t,
		makeReq(http.MethodGet, pathSync+"?addr=:foo", nil),
		newResp(http.StatusBadRequest, errBadSyncAddr.Error()),
	)

	assertResponse(t,
		makeReq(http.MethodGet, pathSync+"?addr=foobar", nil),
		newResp(http.StatusInternalServerError, ""), // The exact error is convoluted, so we skip comparison.
	)
}

func TestStateHandlers(t *testing.T) {
	makeReq := makeRequestFor(createEnclave(&defaultCfg).privSrv)

	tooLargeKey := make([]byte, 1024*1024+1)
	assertResponse(t,
		makeReq(http.MethodPut, pathState, bytes.NewReader(tooLargeKey)),
		newResp(http.StatusInternalServerError, errFailedReqBody.Error()),
	)

	// As long as we don't hit our (generous) upload limit, we always expect an
	// HTTP 200 response.
	almostTooLargeKey := make([]byte, 1024*1024)
	assertResponse(t,
		makeReq(http.MethodPut, pathState, bytes.NewReader(almostTooLargeKey)),
		newResp(http.StatusOK, ""),
	)

	// Subsequent calls to the endpoint overwrite the previous call.
	expected := []byte("foobar")
	assertResponse(t,
		makeReq(http.MethodPut, pathState, bytes.NewReader(expected)),
		newResp(http.StatusOK, ""),
	)

	// Now retrieve the state and make sure that it's what we sent earlier.
	assertResponse(t,
		makeReq(http.MethodGet, pathState, nil),
		newResp(http.StatusOK, string(expected)),
	)
}

func TestProxyHandler(t *testing.T) {
	appPage := "foobar"

	// Nitring acts as a reverse proxy to this Web server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, appPage)
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
	assertResponse(t, resp, newResp(http.StatusOK, indexPage))

	// Request a random page.  Nitriding is going to forwrad the request to our
	// test Web server.
	resp, err = http.Get(nitridingSrv + "/foo/bar")
	if err != nil {
		t.Fatal(err)
	}
	assertResponse(t, resp, newResp(http.StatusOK, appPage))
}

func TestHashHandler(t *testing.T) {
	validHash := [sha256.Size]byte{}
	validHashB64 := base64.StdEncoding.EncodeToString(validHash[:])
	e := createEnclave(&defaultCfg)
	makeReq := makeRequestFor(e.privSrv)

	// Send invalid Base64.
	assertResponse(t,
		makeReq(http.MethodPost, pathHash, bytes.NewBufferString("foo")),
		newResp(http.StatusBadRequest, errNoBase64.Error()),
	)

	// Send invalid hash size.
	assertResponse(t,
		makeReq(http.MethodPost, pathHash, bytes.NewBufferString("AAAAAAAAAAAAAA==")),
		newResp(http.StatusBadRequest, errHashWrongSize.Error()),
	)

	// Send too much data.
	s := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	assertResponse(t,
		makeReq(http.MethodPost, pathHash, bytes.NewBufferString(s)),
		newResp(http.StatusBadRequest, errTooMuchToRead.Error()),
	)

	// Finally, send a valid, Base64-encoded SHA-256 hash.
	assertResponse(t,
		makeReq(http.MethodPost, pathHash, bytes.NewBufferString(validHashB64)),
		newResp(http.StatusOK, ""),
	)

	// Same as above but with an additional \n.
	assertResponse(t,
		makeReq(http.MethodPost, pathHash, bytes.NewBufferString(validHashB64+"\n")),
		newResp(http.StatusOK, ""),
	)

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

func TestAttestationHandlerWhileProfiling(t *testing.T) {
	cfg := defaultCfg
	cfg.UseProfiling = true
	makeReq := makeRequestFor(createEnclave(&cfg).pubSrv)

	// Ensure that the attestation handler aborts if profiling is enabled.
	assertResponse(t,
		makeReq(http.MethodGet, pathAttestation, nil),
		newResp(http.StatusServiceUnavailable, errProfilingSet),
	)
}

func TestAttestationHandler(t *testing.T) {
	makeReq := makeRequestFor(createEnclave(&defaultCfg).pubSrv)

	assertResponse(t,
		makeReq(http.MethodPost, pathAttestation, nil),
		newResp(http.StatusMethodNotAllowed, ""),
	)

	assertResponse(t,
		makeReq(http.MethodGet, pathAttestation, nil),
		newResp(http.StatusBadRequest, errNoNonce),
	)

	assertResponse(t,
		makeReq(http.MethodGet, pathAttestation+"?nonce=foobar", nil),
		newResp(http.StatusBadRequest, errBadNonceFormat),
	)

	// If we are not inside an enclave, attestation is going to result in an
	// error.
	if !inEnclave {
		assertResponse(t,
			makeReq(http.MethodGet, pathAttestation+"?nonce=0000000000000000000000000000000000000000", nil),
			newResp(http.StatusInternalServerError, errFailedAttestation),
		)
	}
}

func TestConfigHandler(t *testing.T) {
	makeReq := makeRequestFor(createEnclave(&defaultCfg).pubSrv)

	assertResponse(t,
		makeReq(http.MethodGet, pathConfig, nil),
		newResp(http.StatusOK, defaultCfg.String()),
	)
}
