# Nitriding

[![GoDoc](https://pkg.go.dev/badge/github.com/brave/nitriding?utm_source=godoc)](https://pkg.go.dev/github.com/brave/nitriding)

This Go tool kit makes it possible to run your application inside an
[AWS Nitro Enclave](https://aws.amazon.com/ec2/nitro/nitro-enclaves/).
Let's assume that you built a Web service in Rust.  You can now use nitriding to
move your Rust code into a secure enclave, making it possible for your users to
remotely verify that you are in fact running the code that you claim to run.
Nitriding provides the following features:

* Automatically obtains an HTTPS certificate (either self-signed or via
  [Let's Encrypt](https://letsencrypt.org))
  for clients to securely connect to your enclave over the Internet.  Nitriding
  can act as a TLS-terminating reverse HTTP proxy for your application, so your
  application does not have to deal with obtaining certificates.

* Automatically exposes an HTTPS endpoint for remote attestation.  After having
  audited your enclave's source code, your users can conveniently verify the
  enclave's image by using a tool like
  [verify-enclave](https://github.com/brave-experiments/verify-enclave)
  and running:

   ```
   make verify CODE=/path/to/code/ ENCLAVE=https://enclave.com/enclave/attestation
   ```

* Are you building an application that uses a protocol other than HTTP?  If so,
  nitriding makes it possible to register a hash over your application's public
  key material which is subsequently included in the
  [attestation document](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html#term-attestdoc).
  This allows your users to verify that their connection is securely terminated
  inside the enclave, regardless of the protocol that you are using.

* Provides an API to scale enclave applications horizontally while synchronizing
  state between enclaves.

* AWS Nitro Enclaves only provide a highly constrained
  [VSOCK channel](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html#term-socket)
  between the enclave and its host.  Nitriding creates TAP interface inside the
  enclave, allowing your application to transparently access the Internet
  without having to worry about VSOCK, port forwarding, or tunneling.

* Automatically initializes the enclave's entropy pool using the Nitro
  hypervisor.

To learn more about nitriding's trust assumptions, architecture, and build
system, take a look at our [research paper](https://arxiv.org/abs/2206.04123).

## Usage

To use nitriding, the following steps are necessary:

1. Make sure that your enclave application supports
   [reproducible builds](https://reproducible-builds.org);
   otherwise, users won't be able to verify your enclave image.

2. Set up
   [this proxy application](https://github.com/containers/gvisor-tap-vsock/tree/main/cmd/gvproxy)
   on the EC2 host.

3. Bundle your application and nitriding together in a Dockerfile.  The
   nitriding stand-alone executable must be invoked first, followed by your
   application.  To build the nitriding executable, run `make cmd/nitriding`.
   (Then, run `./cmd/nitriding -help` to see a list of command line options.)
   For reproducible Docker images, we recommend
   [kaniko](https://github.com/GoogleContainerTools/kaniko)
   and
   [ko](https://github.com/ko-build/ko) (for Go applications only).

4. Once your application is done bootstrapping, it must let nitriding know, so
   it can start the Internet-facing Web server that handles remote attestation
   and other tasks.  To do so, the application must issue an HTTP GET request to
   `http://127.0.0.1:8080/enclave/ready`.  The handler ignores URL parameters
   and responds with a status code 200 if the request succeeded.  Note that the
   port in this example, 8080, is controlled by nitriding's `-intport` command
   line flag.

Take a look at [this example application](example/) to learn how nitriding works
in practice.

## Development

To test and lint the code, run:

```
make
```

## More documentation

* [System architecture](doc/architecture.md)
* [Example application](example/)
