package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"testing"
)

func queryHandler(handler http.HandlerFunc, path string, reader io.Reader) *http.Response {
	req := httptest.NewRequest(http.MethodGet, path, reader)
	rec := httptest.NewRecorder()
	handler(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	return res
}

func TestNonceHandler(t *testing.T) {
	enclave := createEnclave(&defaultCfg)
	res := queryHandler(nonceHandler(enclave), pathNonce, bytes.NewReader([]byte{}))

	// Did the operation succeed?
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code %d but got %d.", http.StatusOK, res.StatusCode)
	}

	// Did we get what looks like a nonce?
	b64Nonce, err := io.ReadAll(res.Body)
	failOnErr(t, err)
	rawNonce, err := base64.StdEncoding.DecodeString(string(b64Nonce))
	if err != nil {
		t.Fatalf("Failed to decode Base64-encoded nonce: %s", err)
	}
	if len(rawNonce) != nonceLen {
		t.Fatalf("Expected nonce length %d but got %d.", nonceLen, len(rawNonce))
	}

	// Was the nonce added to the enclave's nonce cache?
	if !enclave.nonceCache.Exists(strings.TrimSpace(string(b64Nonce))) {
		t.Fatal("Nonce was not added to enclave's nonce cache.")
	}
}

func TestNonceHandlerIfErr(t *testing.T) {
	cryptoRead = func(b []byte) (n int, err error) {
		return 0, errors.New("not enough randomness")
	}
	defer func() {
		cryptoRead = rand.Read
	}()

	res := queryHandler(
		nonceHandler(createEnclave(&defaultCfg)),
		pathNonce,
		bytes.NewReader([]byte{}),
	)

	// Did the operation fail?
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("Expected status code %d but got %d.", http.StatusInternalServerError, res.StatusCode)
	}

	// Did we get the correct error string?
	errMsg, err := io.ReadAll(res.Body)
	failOnErr(t, err)
	if strings.TrimSpace(string(errMsg)) != errFailedNonce.Error() {
		t.Fatalf("Expected error message %q but got %q.", errFailedNonce.Error(), errMsg)
	}
}

func TestRespSyncHandlerForBadReqs(t *testing.T) {
	var res *http.Response
	enclave := createEnclave(&defaultCfg)

	// Send non-Base64 bogus data.
	res = queryHandler(respSyncHandler(enclave), pathSync, strings.NewReader("foobar!"))
	expect(t, res, http.StatusInternalServerError, errNoBase64.Error())

	// Send Base64-encoded bogus data.
	res = queryHandler(respSyncHandler(enclave), pathSync, strings.NewReader("Zm9vYmFyCg=="))
	expect(t, res, http.StatusUnauthorized, errFailedVerify.Error())
}

func TestRespSyncHandler(t *testing.T) {
	var res *http.Response
	enclave := createEnclave(&defaultCfg)
	enclave.nonceCache.Add(initAttInfo.nonce.B64())

	// Mock functions for our tests to pass.
	getPCRValues = func() (map[uint][]byte, error) {
		return initAttInfo.pcr, nil
	}
	currentTime = func() time.Time { return initAttInfo.attDocTime }

	res = queryHandler(respSyncHandler(enclave), pathSync, strings.NewReader(initAttInfo.attDoc))
	// On a non-enclave platform, the responder code will get as far as to
	// request its attestation document.
	expect(t, res, http.StatusInternalServerError, errFailedAttestation)
}

func TestRespSyncHandlerDoS(t *testing.T) {
	var res *http.Response
	enclave := createEnclave(&defaultCfg)

	// Send more data than the handler should be willing to read.
	maxSize := base64.StdEncoding.EncodedLen(maxAttDocLen)
	body := make([]byte, maxSize+1)
	res = queryHandler(respSyncHandler(enclave), pathSync, bytes.NewReader(body))
	expect(t, res, http.StatusInternalServerError, errFailedRespBody.Error())
}

var initAttInfo = &remoteAttInfo{
	pubKey: [boxKeyLen]byte{
		213, 156, 108, 34, 179, 183, 69, 26, 209, 218, 58, 186, 9, 32, 237,
		253, 46, 80, 36, 200, 169, 239, 97, 200, 17, 188, 203, 99, 151, 40,
		10, 113,
	},
	privKey: [boxKeyLen]byte{
		74, 137, 121, 11, 209, 38, 48, 48, 167, 157, 184, 58, 2, 110, 9, 204,
		174, 148, 243, 154, 191, 74, 118, 90, 11, 240, 246, 131, 187, 157,
		157, 25,
	},
	nonce: nonce{},
	pcr: map[uint][]byte{
		0: {
			0xda, 0x54, 0x6f, 0x8d, 0xda, 0x37, 0x52, 0x19, 0x45, 0xdf, 0x4a,
			0x6d, 0x3e, 0x39, 0x70, 0x63, 0x58, 0x8c, 0xd5, 0xf8, 0x70, 0xaa,
			0xa0, 0x7a, 0x62, 0xe9, 0x67, 0xb2, 0x54, 0xd5, 0xf8, 0x17, 0x6d,
			0xaa, 0x96, 0xec, 0x83, 0xcd, 0xc5, 0x40, 0x2b, 0x0b, 0x52, 0x7a,
			0x16, 0x24, 0x72, 0xb5},
		1: {
			0xbc, 0xdf, 0x05, 0xfe, 0xfc, 0xca, 0xa8, 0xe5, 0x5b, 0xf2, 0xc8,
			0xd6, 0xde, 0xe9, 0xe7, 0x9b, 0xbf, 0xf3, 0x1e, 0x34, 0xbf, 0x28,
			0xa9, 0x9a, 0xa1, 0x9e, 0x6b, 0x29, 0xc3, 0x7e, 0xe8, 0x0b, 0x21,
			0x4a, 0x41, 0x4b, 0x76, 0x07, 0x23, 0x6e, 0xdf, 0x26, 0xfc, 0xb7,
			0x86, 0x54, 0xe6, 0x3f},
		2: {
			0x45, 0xaa, 0xd9, 0xf5, 0xc3, 0x9a, 0x90, 0x5b, 0x9f, 0xef, 0xac,
			0x05, 0x56, 0x87, 0x0a, 0x20, 0xd1, 0x6f, 0x3f, 0x3c, 0x21, 0xcf,
			0x93, 0x3e, 0x60, 0x64, 0xff, 0xf9, 0x24, 0xaf, 0x9c, 0x13, 0xed,
			0x26, 0xab, 0x6d, 0x56, 0x3e, 0x27, 0x2b, 0x85, 0xe7, 0xc3, 0x17,
			0x0f, 0x01, 0xac, 0xda},
		3: null,
		4: {
			0xd8, 0xa8, 0xe8, 0xee, 0xe9, 0x6d, 0x81, 0xb7, 0x7a, 0x25, 0x14,
			0x10, 0xb7, 0xa9, 0xb1, 0x80, 0x78, 0x76, 0x53, 0xf1, 0x25, 0xd1,
			0xdb, 0xca, 0x79, 0x68, 0x5c, 0x93, 0xfb, 0x88, 0x5b, 0x33, 0x5e,
			0x0b, 0x8d, 0x17, 0x2c, 0x98, 0x21, 0xa8, 0x62, 0x51, 0x5a, 0x60,
			0x3c, 0xc3, 0x3a, 0xb2},
		5:  null,
		6:  null,
		7:  null,
		8:  null,
		9:  null,
		10: null,
		11: null,
		12: null,
		13: null,
		14: null,
		15: null,
	},
	attDocTime: mustParse("2022-08-04T20:00:00Z"),
	// The following attestation document was generated on 2022-08-04 and
	// contains a nonce (set to all 0 bytes), user data (contains a nonce and
	// is set to all 0 bytes), and a public key (contains an NaCl public key).
	attDoc: `
hEShATgioFkRB6lpbW9kdWxlX2lkeCdpLTA4MDk4NDk3MTBiZjFiNjFiLWVuYzAxODI2YTQ0OWEwMGI
xN2FmZGlnZXN0ZlNIQTM4NGl0aW1lc3RhbXAbAAABgmpE949kcGNyc7AAWDDaVG+N2jdSGUXfSm0+OX
BjWIzV+HCqoHpi6WeyVNX4F22qluyDzcVAKwtSehYkcrUBWDC83wX+/Mqo5VvyyNbe6eebv/MeNL8oq
Zqhnmspw37oCyFKQUt2ByNu3yb8t4ZU5j8CWDBFqtn1w5qQW5/vrAVWhwog0W8/PCHPkz5gZP/5JK+c
E+0mq21WPicrhefDFw8BrNoDWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAEWDDYqOju6W2Bt3olFBC3qbGAeHZT8SXR28p5aFyT+4hbM14LjRcsmCGoYlFaYDzDOr
IFWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGWDAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHWDAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAKWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAALWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAMWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANWDAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOWDAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPWDAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABrY2VydGlmaWNhdGVZAoAwggJ8MIICAaADAgECAhAB
gmpEmgCxegAAAABi7BnHMAoGCCqGSM49BAMDMIGOMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGl
uZ3RvbjEQMA4GA1UEBwwHU2VhdHRsZTEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxOTA3Bg
NVBAMMMGktMDgwOTg0OTcxMGJmMWI2MWIudXMtZWFzdC0yLmF3cy5uaXRyby1lbmNsYXZlczAeFw0yM
jA4MDQxOTExMDBaFw0yMjA4MDQyMjExMDNaMIGTMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGlu
Z3RvbjEQMA4GA1UEBwwHU2VhdHRsZTEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxPjA8BgN
VBAMMNWktMDgwOTg0OTcxMGJmMWI2MWItZW5jMDE4MjZhNDQ5YTAwYjE3YS51cy1lYXN0LTIuYXdzMH
YwEAYHKoZIzj0CAQYFK4EEACIDYgAEpy6eKLNsGy1mhV9SjR5Yj1Wn3wGmX87HinGw/jjpz/Ij3JsGO
HoF0Ve7wtVGgHxT0MjRh/1a45Zd39zpWMyc06tiN6ZM9S9GKws23tPr826TGE9PNB4jQhsNv8gHEJT3
ox0wGzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIGwDAKBggqhkjOPQQDAwNpADBmAjEA8SBbh3YYlv/
XZPttIR9m43jTNkgUHkWyB9hxhWkVEjnfb3MDqAPFhMh5BFoArDD0AjEAj3XawBSe5AK9842TdW/mt+
C0e/OSZpaFAJqvTAX9MNX3wSEm/Jron+wtoVb+DecTaGNhYnVuZGxlhFkCFTCCAhEwggGWoAMCAQICE
QD5MXVoG5Cv4R1GzLTk5/hWMAoGCCqGSM49BAMDMEkxCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZBbWF6
b24xDDAKBgNVBAsMA0FXUzEbMBkGA1UEAwwSYXdzLm5pdHJvLWVuY2xhdmVzMB4XDTE5MTAyODEzMjg
wNVoXDTQ5MTAyODE0MjgwNVowSTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECw
wDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT8A
lTrpgjB82hw4prakL5GODKSc26JS//2ctmJREtQUeU0pLH22+PAvFgaMrexdgcO3hLWmj/qIRtm51LP
fdHdCV9vE3D0FwhD2dwQASHkz2MBKAlmRIfJeWKEME3FP/SjQjBAMA8GA1UdEwEB/wQFMAMBAf8wHQY
DVR0OBBYEFJAltQ3ZBUfnlsOW+nKdz5mp30uWMA4GA1UdDwEB/wQEAwIBhjAKBggqhkjOPQQDAwNpAD
BmAjEAo38vkaHJvV7nuGJ8FpjSVQOOHwND+VtjqWKMPTmAlUWhHry/LjtV2K7ucbTD1q3zAjEAovObF
gWycCil3UugabUBbmW0+96P4AYdalMZf5za9dlDvGH8K+sDy2/ujSMC89/2WQLBMIICvTCCAkSgAwIB
AgIQQpblfNs/3yOBCWXcu04/WDAKBggqhkjOPQQDAzBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1
hem9uMQwwCgYDVQQLDANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczAeFw0yMjA4MDQwNT
Q4MDhaFw0yMjA4MjQwNjQ4MDhaMGQxCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZBbWF6b24xDDAKBgNVB
AsMA0FXUzE2MDQGA1UEAwwtOWUyOTllNTRmZTE2M2Q1YS51cy1lYXN0LTIuYXdzLm5pdHJvLWVuY2xh
dmVzMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEzjYIWIyVfPvNjCsLf8VS2P1R1lmaMox7vIOWVU5sfCp
/kyhzz1RLlKTPZLXRfpVZWT8F58ygN3AAzjqOfS8HzWRwfmH0kTsP9T/U2kLYIEYlEPv7Qw98U/1+Wx
VpP94zo4HVMIHSMBIGA1UdEwEB/wQIMAYBAf8CAQIwHwYDVR0jBBgwFoAUkCW1DdkFR+eWw5b6cp3Pm
anfS5YwHQYDVR0OBBYEFPjkq4ZrPqs7R5KtXk3YYASqnwhwMA4GA1UdDwEB/wQEAwIBhjBsBgNVHR8E
ZTBjMGGgX6BdhltodHRwOi8vYXdzLW5pdHJvLWVuY2xhdmVzLWNybC5zMy5hbWF6b25hd3MuY29tL2N
ybC9hYjQ5NjBjYy03ZDYzLTQyYmQtOWU5Zi01OTMzOGNiNjdmODQuY3JsMAoGCCqGSM49BAMDA2cAMG
QCMHXCswA211klCMLW+p3sD8sces9/WEEuIxeaQ1lwKfbCW9yWN7ynujRz01+W378qBgIwXoEP9UIQ2
p7oC7+HJYp/GNiFrYg4mwEETh75CWX38CFEIyZtbx9abI8pb3bQ+zaZWQMZMIIDFTCCApugAwIBAgIR
ANSXsgCDg5YY9m4w3HzTIQ8wCgYIKoZIzj0EAwMwZDELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXp
vbjEMMAoGA1UECwwDQVdTMTYwNAYDVQQDDC05ZTI5OWU1NGZlMTYzZDVhLnVzLWVhc3QtMi5hd3Mubm
l0cm8tZW5jbGF2ZXMwHhcNMjIwODA0MTU1MDI2WhcNMjIwODEwMTY1MDI1WjCBiTE8MDoGA1UEAwwzN
2MwM2Q3ZjMxM2IzZDdiOC56b25hbC51cy1lYXN0LTIuYXdzLm5pdHJvLWVuY2xhdmVzMQwwCgYDVQQL
DANBV1MxDzANBgNVBAoMBkFtYXpvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMRAwDgYDVQQHDAd
TZWF0dGxlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEjh5qz+Cx8rHDYKvh1E7GqR+GDG/g5CzjPBiu+p
krFdYe8AN58lfwHv2+YN6i+lOmjpjFADefv6yBS7Va7Ddj6DB3cJWcOhOlKqIyDZpZ4yDeG5H2TvxGi
IR+1vFPFDKZo4HqMIHnMBIGA1UdEwEB/wQIMAYBAf8CAQEwHwYDVR0jBBgwFoAU+OSrhms+qztHkq1e
TdhgBKqfCHAwHQYDVR0OBBYEFGLAF3Hq2WorIwNXLsBHMR4s0uD1MA4GA1UdDwEB/wQEAwIBhjCBgAY
DVR0fBHkwdzB1oHOgcYZvaHR0cDovL2NybC11cy1lYXN0LTItYXdzLW5pdHJvLWVuY2xhdmVzLnMzLn
VzLWVhc3QtMi5hbWF6b25hd3MuY29tL2NybC83MjJlMzIxYy1mYTdmLTRjZjQtYjljMS00YzQ0YzFiN
2M3OWQuY3JsMAoGCCqGSM49BAMDA2gAMGUCMCC/N/6QnA+LQgtLMZhqSXcq8stbOQZ7PTZ6uOK6XcO2
FC6huMamexK3bkjXQ9tUzgIxANwt5DWIAvBA1hfn1wBl7gQqz1bSlenLqz0ZFyxFW4sT0/rur4ui7OG
JCF5IG4P8zVkCgTCCAn0wggIEoAMCAQICFHPGskW4/ej8wLV8S9yhPGlYOibuMAoGCCqGSM49BAMDMI
GJMTwwOgYDVQQDDDM3YzAzZDdmMzEzYjNkN2I4LnpvbmFsLnVzLWVhc3QtMi5hd3Mubml0cm8tZW5jb
GF2ZXMxDDAKBgNVBAsMA0FXUzEPMA0GA1UECgwGQW1hem9uMQswCQYDVQQGEwJVUzELMAkGA1UECAwC
V0ExEDAOBgNVBAcMB1NlYXR0bGUwHhcNMjIwODA0MTcyMjMyWhcNMjIwODA1MTcyMjMyWjCBjjELMAk
GA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxDzANBgNVBAoMBk
FtYXpvbjEMMAoGA1UECwwDQVdTMTkwNwYDVQQDDDBpLTA4MDk4NDk3MTBiZjFiNjFiLnVzLWVhc3QtM
i5hd3Mubml0cm8tZW5jbGF2ZXMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAR2rjayOwUyMHjfs8D7fnHI
RJ87kcByyC0wB4dzk2uO7Sj68ebIsCiMIZIzr8wDfNqODM4FJqrX0NMq57X66Mdm3uasyse1NummrUu
RiUf0kx0o7aHimZ+RSzGMrDCTNNCjJjAkMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAg
IEMAoGCCqGSM49BAMDA2cAMGQCMCyFFdZ9EjHxnY9dnOnTevkwJFOYEmLsSQAzl2D6X64LpuuKunhnr
VGEE8wz7lxwZgIwaRQAmr0Ke/l2wNI5UcWoov7VVYoVgbA/VudK7x85KMoqRH+N/IRXcgQWAlw3pZv8
anB1YmxpY19rZXlYINWcbCKzt0Ua0do6ugkg7f0uUCTIqe9hyBG8y2OXKApxaXVzZXJfZGF0YVQAAAA
AAAAAAAAAAAAAAAAAAAAAAGVub25jZVQAAAAAAAAAAAAAAAAAAAAAAAAAAFhgUx278a0ygjrmIGtSIe
WlqX/lNr5cx9VZAFb5rFJ6igkZsFxwmk764LQEcCE7sifYTKvf/4jpKGdTw+wwmu+Ekdqhi0rmm7dgG
PxIqEgb+JWZGN+Ke5HwVMMGoboAYCXw`,
}
