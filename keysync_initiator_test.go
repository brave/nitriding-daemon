package nitriding

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRequestNonce(t *testing.T) {
	expNonce := nonce{
		0x14, 0x56, 0x82, 0x13, 0x1f, 0xff, 0x9c, 0xf7, 0xeb, 0xb6,
		0x9e, 0x7b, 0xea, 0x29, 0x16, 0x49, 0xeb, 0x03, 0xa2, 0x47,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, expNonce.B64())
	}))
	defer srv.Close()

	retNonce, err := requestNonce(srv.URL)
	if err != nil {
		t.Fatalf("Failed to request nonce: %s", err)
	}
	if expNonce != retNonce {
		t.Fatal("Returned nonce not as expected.")
	}
}

func TestRequestNonceDoS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce1 := nonce{}
		nonce2 := nonce{}
		fmt.Fprintf(w, "%s%s", nonce1.B64(), nonce2.B64())
	}))
	defer srv.Close()

	if _, err := requestNonce(srv.URL); err == nil {
		t.Fatal("Client code should have rejected long response body but didn't.")
	}
}

func TestRequestAttDoc(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "foobar")
	}))
	defer srv.Close()

	_, err := requestAttDoc(srv.URL, []byte{})
	if err == nil {
		t.Fatal("Client code should have rejected non-Base64 data but didn't.")
	}
}

func TestRequestAttDocDoS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		maxReadLen := base64.StdEncoding.EncodedLen(maxAttDocLen)
		// Send one byte more than the client is willing to read.
		buf := make([]byte, maxReadLen+1)
		fmt.Fprintln(w, buf)
	}))
	defer srv.Close()

	if _, err := requestAttDoc(srv.URL, []byte{}); err == nil {
		t.Fatal("Client code should have rejected long response body but didn't.")
	}
}

func TestProcessAttDoc(t *testing.T) {
	// Mock functions for our tests to pass.
	getPCRValues = func() (map[uint][]byte, error) {
		return respAttInfo.pcr, nil
	}
	currentTime = func() time.Time { return respAttInfo.attDocTime }

	rawAttDoc, err := base64.StdEncoding.DecodeString(respAttInfo.attDoc)
	if err != nil {
		t.Fatalf("Failed to Base64-decode attestation document: %s", err)
	}
	keyMaterial := struct {
		SecretKey string `json:"secret_key"`
	}{}

	if err := processAttDoc(
		rawAttDoc,
		&respAttInfo.nonce,
		&boxKey{
			pubKey:  &respAttInfo.pubKey,
			privKey: &respAttInfo.privKey,
		},
		&keyMaterial,
	); err != nil {
		t.Fatalf("Failed to verify valid attestation document: %s", err)
	}

	// Make sure that processAttDoc successfully decrypted and recovered the
	// secret key material, "foobar".
	if keyMaterial.SecretKey != "foobar" {
		t.Fatalf("Expected secret key 'foobar' but got %q.", keyMaterial.SecretKey)
	}
}

var respAttInfo = &remoteAttInfo{
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
		0: []byte{
			0xb0, 0x61, 0xbc, 0xe3, 0x1a, 0x85, 0x50, 0xc2, 0x4c, 0xb8,
			0xc1, 0xdc, 0x0e, 0x53, 0x98, 0xe5, 0xc8, 0x0f, 0xab, 0xa6,
			0x7f, 0x75, 0xfd, 0x3b, 0x06, 0x21, 0xc0, 0xb8, 0x66, 0x36,
			0xfc, 0xe0, 0xd6, 0x4c, 0x4d, 0x7d, 0x37, 0x47, 0x89, 0x08,
			0xe1, 0xf8, 0xfc, 0xe9, 0xdf, 0x66, 0xe1, 0xb9},
		1: []byte{
			0xbc, 0xdf, 0x05, 0xfe, 0xfc, 0xca, 0xa8, 0xe5, 0x5b, 0xf2,
			0xc8, 0xd6, 0xde, 0xe9, 0xe7, 0x9b, 0xbf, 0xf3, 0x1e, 0x34,
			0xbf, 0x28, 0xa9, 0x9a, 0xa1, 0x9e, 0x6b, 0x29, 0xc3, 0x7e,
			0xe8, 0x0b, 0x21, 0x4a, 0x41, 0x4b, 0x76, 0x07, 0x23, 0x6e,
			0xdf, 0x26, 0xfc, 0xb7, 0x86, 0x54, 0xe6, 0x3f},
		2: []byte{
			0x6a, 0xe6, 0x79, 0x76, 0xd7, 0x40, 0x38, 0x0d, 0x50, 0x64,
			0x36, 0x91, 0xac, 0x3a, 0xae, 0xbb, 0xa6, 0x0f, 0x27, 0xd7,
			0xb8, 0xa0, 0xe1, 0xa9, 0xea, 0xf2, 0x38, 0x6d, 0x25, 0xee,
			0xab, 0x88, 0x1c, 0x09, 0xac, 0xc5, 0xc8, 0x09, 0xeb, 0xec,
			0xf9, 0x9b, 0x49, 0x71, 0x05, 0xf6, 0xcb, 0x5b},
		3: null,
		4: []byte{
			0xd8, 0xa8, 0xe8, 0xee, 0xe9, 0x6d, 0x81, 0xb7, 0x7a, 0x25,
			0x14, 0x10, 0xb7, 0xa9, 0xb1, 0x80, 0x78, 0x76, 0x53, 0xf1,
			0x25, 0xd1, 0xdb, 0xca, 0x79, 0x68, 0x5c, 0x93, 0xfb, 0x88,
			0x5b, 0x33, 0x5e, 0x0b, 0x8d, 0x17, 0x2c, 0x98, 0x21, 0xa8,
			0x62, 0x51, 0x5a, 0x60, 0x3c, 0xc3, 0x3a, 0xb2},
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
	attDocTime: mustParse("2022-07-27T05:00:00Z"),
	// The following attestation document was generated on 2022-07-27 and
	// contains a nonce (set to all 0 bytes) and user data (contains encrypted
	// key information).
	attDoc: `
hEShATgioFkRG6lpbW9kdWxlX2lkeCdpLTA4MDk4NDk3MTBiZjFiNjFiLWVuYzAxODIzZDY0M2U2Mzl
hYTBmZGlnZXN0ZlNIQTM4NGl0aW1lc3RhbXAbAAABgj1kWVpkcGNyc7AAWDCwYbzjGoVQwky4wdwOU5
jlyA+rpn91/TsGIcC4Zjb84NZMTX03R4kI4fj86d9m4bkBWDC83wX+/Mqo5VvyyNbe6eebv/MeNL8oq
Zqhnmspw37oCyFKQUt2ByNu3yb8t4ZU5j8CWDBq5nl210A4DVBkNpGsOq67pg8n17ig4anq8jhtJe6r
iBwJrMXICevs+ZtJcQX2y1sDWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
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
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABrY2VydGlmaWNhdGVZAn8wggJ7MIICAaADAgECAhAB
gj1kPmOaoAAAAABi4JzCMAoGCCqGSM49BAMDMIGOMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGl
uZ3RvbjEQMA4GA1UEBwwHU2VhdHRsZTEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxOTA3Bg
NVBAMMMGktMDgwOTg0OTcxMGJmMWI2MWIudXMtZWFzdC0yLmF3cy5uaXRyby1lbmNsYXZlczAeFw0yM
jA3MjcwMjAyMzlaFw0yMjA3MjcwNTAyNDJaMIGTMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGlu
Z3RvbjEQMA4GA1UEBwwHU2VhdHRsZTEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxPjA8BgN
VBAMMNWktMDgwOTg0OTcxMGJmMWI2MWItZW5jMDE4MjNkNjQzZTYzOWFhMC51cy1lYXN0LTIuYXdzMH
YwEAYHKoZIzj0CAQYFK4EEACIDYgAE7il+oEijv6hrLpdsG4T/TbjSNxla6LnM2/2IGyCFNblCghVv1
VNv7JF1zu+pP4jT7VbeVEj2z5T0lQMc/bLLxXUcbVlaA8qzAIX5yTkwAA53zU6m7frzvWVwdSuSNvXw
ox0wGzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIGwDAKBggqhkjOPQQDAwNoADBlAjEAiKzrNPjQug4
lt4wfSuIxvyr4BoiS0en2pLM7NtI9QnQKwXKT7V1Rk4oKr7zVBeiJAjAMnKjSMZn3cID2nL55qgoeCF
0PXntyuGXwkh8J5bsN5BUKP38CiqmONjvyxPOiQWpoY2FidW5kbGWEWQIVMIICETCCAZagAwIBAgIRA
PkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpv
bjEMMAoGA1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA
1WhcNNDkxMDI4MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDA
NBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEGBSuBBAAiA2IABPwCV
OumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs99
0d0JX28TcPQXCEPZ3BABIeTPYwEoCWZEh8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgN
VHQ4EFgQUkCW1DdkFR+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMG
YCMQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPWrfMCMQCi85sWB
bJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6NIwLz3/ZZAsIwggK+MIICRKADAgEC
AhA990CB9kGNMZfvZChwdlgnMAoGCCqGSM49BAMDMEkxCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZBbWF
6b24xDDAKBgNVBAsMA0FXUzEbMBkGA1UEAwwSYXdzLm5pdHJvLWVuY2xhdmVzMB4XDTIyMDcyNTA2ND
gwOFoXDTIyMDgxNDA3NDgwOFowZDELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UEC
wwDQVdTMTYwNAYDVQQDDC05ZjJmYTNhYWRlZTBhMzZhLnVzLWVhc3QtMi5hd3Mubml0cm8tZW5jbGF2
ZXMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASJrZH+NsENK8xQ+r4qIT56spgyQ0rqLuQOUv7CmfHg19Z
giX4k1tUbTIGc1hFVphxMaahoM6N3e1mBRMkX9Y/gxYmPnSrom/cq6BnWW8yYWpocaFuXqq/VjOJ9Ba
TcO4qjgdUwgdIwEgYDVR0TAQH/BAgwBgEB/wIBAjAfBgNVHSMEGDAWgBSQJbUN2QVH55bDlvpync+Zq
d9LljAdBgNVHQ4EFgQUPZaPBc+bF0kz5B3MQi4KoWP+hRIwDgYDVR0PAQH/BAQDAgGGMGwGA1UdHwRl
MGMwYaBfoF2GW2h0dHA6Ly9hd3Mtbml0cm8tZW5jbGF2ZXMtY3JsLnMzLmFtYXpvbmF3cy5jb20vY3J
sL2FiNDk2MGNjLTdkNjMtNDJiZC05ZTlmLTU5MzM4Y2I2N2Y4NC5jcmwwCgYIKoZIzj0EAwMDaAAwZQ
IxANMhikJw9gtb6vBdlgVKT1gOgX8g8HhmL764kGCqNUcQEx87vPMhiVamVtUsCIB/awIwbV4Neqsy1
H4Cq3JWZG9lR2+D8s+nMCVDpUlThEK2K8p0EJP5lPF8N5e0V8oZuA0JWQMYMIIDFDCCApqgAwIBAgIQ
NF6Fd19DpZgwKsWQtzHX8TAKBggqhkjOPQQDAzBkMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9
uMQwwCgYDVQQLDANBV1MxNjA0BgNVBAMMLTlmMmZhM2FhZGVlMGEzNmEudXMtZWFzdC0yLmF3cy5uaX
Ryby1lbmNsYXZlczAeFw0yMjA3MjYxMTQ1MDBaFw0yMjA4MDEwNDQ0NTlaMIGJMTwwOgYDVQQDDDM0M
TE4MGUyNmU3ZWNjNWY0LnpvbmFsLnVzLWVhc3QtMi5hd3Mubml0cm8tZW5jbGF2ZXMxDDAKBgNVBAsM
A0FXUzEPMA0GA1UECgwGQW1hem9uMQswCQYDVQQGEwJVUzELMAkGA1UECAwCV0ExEDAOBgNVBAcMB1N
lYXR0bGUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARay8thWSHgPinGev1LSpKiNMhpY3uGlzdNtGrl4D
vRC3tYm3e4y1WC8zjR96rPEPqPaImtmJ4GuXUC8oP5u1g4Cr4jFqqL4KwvwvZFeOhY5FdIEidNByaFQ
1PmdLWM7OGjgeowgecwEgYDVR0TAQH/BAgwBgEB/wIBATAfBgNVHSMEGDAWgBQ9lo8Fz5sXSTPkHcxC
LgqhY/6FEjAdBgNVHQ4EFgQUQjKkC8oNyrWpWkdVSGw8wOOYa9IwDgYDVR0PAQH/BAQDAgGGMIGABgN
VHR8EeTB3MHWgc6Bxhm9odHRwOi8vY3JsLXVzLWVhc3QtMi1hd3Mtbml0cm8tZW5jbGF2ZXMuczMudX
MtZWFzdC0yLmFtYXpvbmF3cy5jb20vY3JsLzI1NDY2N2JmLWY2ZDMtNDNlZS1iMGNiLTYyZWNmZWNiZ
TZmMS5jcmwwCgYIKoZIzj0EAwMDaAAwZQIxAKuYyI19bA8mHLo88O1epcirSbOfK348e6SbhdyJazZb
cIkko5zyvgKmskjACB2IpwIwVo0cIeP+2C4L+5CW8iVr5DrRVhtESi+qta4DzYNJlUXl2X3HiV23fqz
2/3XY9uyqWQKCMIICfjCCAgSgAwIBAgIUfFo+I5v6VGh7k5qouGsLv7Mv57owCgYIKoZIzj0EAwMwgY
kxPDA6BgNVBAMMMzQxMTgwZTI2ZTdlY2M1ZjQuem9uYWwudXMtZWFzdC0yLmF3cy5uaXRyby1lbmNsY
XZlczEMMAoGA1UECwwDQVdTMQ8wDQYDVQQKDAZBbWF6b24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJX
QTEQMA4GA1UEBwwHU2VhdHRsZTAeFw0yMjA3MjYxNzIyMThaFw0yMjA3MjcxNzIyMThaMIGOMQswCQY
DVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjEQMA4GA1UEBwwHU2VhdHRsZTEPMA0GA1UECgwGQW
1hem9uMQwwCgYDVQQLDANBV1MxOTA3BgNVBAMMMGktMDgwOTg0OTcxMGJmMWI2MWIudXMtZWFzdC0yL
mF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEGBSuBBAAiA2IABHauNrI7BTIweN+zwPt+cchE
nzuRwHLILTAHh3OTa47tKPrx5siwKIwhkjOvzAN82o4MzgUmqtfQ0yrntfrox2be5qzKx7U26aatS5G
JR/STHSjtoeKZn5FLMYysMJM00KMmMCQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAg
QwCgYIKoZIzj0EAwMDaAAwZQIxAK5vbx5ZauD2RpeK2+v3u37cc9imCrMvF1JY4zbZ3ZZQ8UYa/HjnP
iB3pGd8whiA7wIwNiE2h4KKQEhF4Ory87EpxJCT39uXxVByr5TWQ89Ruj1rB2JSXU1psJ8GxlCkcBVD
anB1YmxpY19rZXn2aXVzZXJfZGF0YVhI4nBS+mXu8vE1TpAF0X8GLthggVJB44h4AnNzMvCtD3Qlagn
FYcA3/G9DXSk1uaaVLTm/O4nVtbjo4MaU8C2rqO94hvbTrml7ZW5vbmNlVAAAAAAAAAAAAAAAAAAAAA
AAAAAAWGDMVPwPgNQE0B4IvYVyzsWa6IguwPxu4RrKW7SzNkcv9b0RySXdAAPD071+Ju6Ic8Pr4EOyd
ac+wcqKQm4ZH3U5+yel2+YU33Tq/WvX1Ra2xmQsgQj3xqcL9XMBbdmNW8M=`,
}
