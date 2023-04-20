## Usage

This document explains how you can build your enclave application on top of
nitriding.  The following steps are necessary.

1. Make sure that your enclave application supports [reproducible
   builds](https://reproducible-builds.org); otherwise, users won't be able to
   verify your enclave image.  Both Rust and Go support reproducible builds
   although some effort may be necessary to get there.
   [Nitriding's Makefile](../cmd/Makefile) shows how one can build a Go program
   reproducibly.

2. Set up
   [this proxy application](https://github.com/containers/gvisor-tap-vsock/tree/main/cmd/gvproxy)
   on the EC2 host.  Run it as follows:
   ```
   gvproxy -listen vsock://:1024 -listen unix:///tmp/network.sock
   ```
   Next, tell the proxy application to forward port 443 to nitriding.
   ```
   curl \
     --unix-socket /tmp/network.sock \
     http:/unix/services/forwarder/expose \
     -X POST \
     -d '{"local":":443","remote":"192.168.127.2:443"}'
   ```
   In case you're wondering, 192.168.127.2 is nitriding's static IP address in
   the private network between gvproxy and nitriding.  Does your enclave
   application expose any other ports?  If so, you have to forward these ports
   too.

3. Build the nitriding executable by running `make cmd/nitriding`.
   (Then, run `./cmd/nitriding -help` to see a list of command line options.)
   For reproducible Docker images, we recommend
   [kaniko](https://github.com/GoogleContainerTools/kaniko)
   or
   [ko](https://github.com/ko-build/ko) (for Go applications only).
   Take a look at [this
   Makefile](https://github.com/brave/star-randsrv/blob/main/Makefile) to see
   an application of kaniko.

3. Bundle the freshly-compiled nitriding and your enclave application together
   in a Dockerfile.  The nitriding stand-alone executable must be invoked
   first, followed by your application.  There are two ways to go about this.
   First, you can create a shell script that first starts nitriding in the
   background, followed by the enclave application.  [Here's an
   example](../example/start.sh).  Second, you can tell nitriding to start your
   enclave application for you:
   ```
   nitriding -appcmd "my-enclave-app -s foo"
   ```
   This instructs nitriding to invoke the command `my-enclave-app -s foo`.
   Nitriding keeps running as long as my-enclave-app is running.

4. There's one more thing, but only if you invoked nitriding with the flag
   `-wait-for-app`: Once your application is done bootstrapping, it must let
   nitriding know, so it can start the Internet-facing Web server that handles
   remote attestation and other tasks.  To do so, the application must issue an
   HTTP GET request to `http://127.0.0.1:8080/enclave/ready`.  The handler
   ignores URL parameters and responds with a status code 200 if the request
   succeeded.  Note that the port in this example, 8080, is controlled by
   nitriding's `-intport` command line flag.  Ignore this paragraph if you did
   not use `-wait-for-app`.

Finally, take a look at
[this example application](example/)
or 
[this production application](https://github.com/brave/star-randsrv/)
to learn how one can build on top of nitriding.
