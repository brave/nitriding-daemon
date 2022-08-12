# Nitriding

[![GoDoc](https://pkg.go.dev/badge/github.com/brave/nitriding?utm_source=godoc)](https://pkg.go.dev/github.com/brave/nitriding)

This package helps with building Go-based Web applications on top of AWS Nitro
Enclaves.  The package provides the following features:

1. Automatically obtains an HTTPS certificate (either self-signed or via [Let's
   Encrypt](https://letsencrypt.org)) for clients to securely connect to your
   enclave over the Internet.

2. Automatically exposes an HTTPS endpoint for remote attestation.  After
   having audited your enclave's source code, your users can conveniently
   verify the enclave by using a tool like
   [verify-enclave](https://github.com/brave-experiments/verify-enclave)
   and running:

   ```
   make verify CODE=/path/to/code/ ENCLAVE=https://example.com/attest
   ```

3. Provides an API for the enclave application to securely share confidential
   key material with an identical, remote enclave.

4. Starts a proxy component that transparently translates between IP and VSOCK,
   so you can write IP-based networking code without having to worry about
   the enclave's constrained VSOCK interface.

5. Automatically initializes the enclave's entropy pool using the Nitro
   hypervisor.

To learn more about nitriding's trust assumptions, architecture, and build
system, take a look at our [research paper](https://arxiv.org/abs/2206.04123).

## Configuration

Nitriding's
[configuration object](https://pkg.go.dev/github.com/brave-experiments/nitriding#Config)
contains comments that explain the purpose of each variable.

## Example

Use the following "hello world" example to get started.  The program
instantiates a new Web server that's listening on port 8443, for the domain
example.com.  It also registers an HTTP handler for the path `/hello-world`
which, when accessed, simply responds with the string "hello world".

Note that in order for this example to work, you need to set up two programs on
the parent EC2 instance:

1. [viproxy](https://github.com/brave/viproxy) by running:

   ```bash
   export CID=5 # The CID you assigned when running "nitro-cli run-enclave --enclave-cid X ...".
   export IN_ADDRS=":8443,:80,3:80"
   export OUT_ADDRS="${CID}:8443,${CID}:80,127.0.0.1:1080"
   viproxy
   ```

2. A SOCKS proxy, e.g.
   [this one](https://github.com/brave-intl/bat-go/tree/nitro-utils/nitro-shim/tools/socksproxy).

That said, here is the enclave application:

```golang
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/brave/nitriding"
)

func helloWorldHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "hello world")
}

func main() {
	enclave := nitriding.NewEnclave(
		&nitriding.Config{
			FQDN:    "example.com",
			Port:    8443,
			UseACME: true,
		},
	)
	enclave.AddRoute(http.MethodGet, "/hello-world", helloWorldHandler)
	if err := enclave.Start(); err != nil {
		log.Fatalf("Enclave terminated: %v", err)
	}
}
```

## Development

To test and lint the code, run:

```
make
```
