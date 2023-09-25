<div align="center">
  <img src="./doc/nitriding-logo.svg" alt="Nitriding logo" width="250">
</div>

---

[![GoDoc](https://pkg.go.dev/badge/github.com/brave/nitriding-daemon?utm_source=godoc)](https://pkg.go.dev/github.com/brave/nitriding-daemon)

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

## More documentation

* [How to use nitriding](doc/usage.md)
* [System architecture](doc/architecture.md)
* [HTTP API](doc/http-api.md)
* [Horizontal scaling](doc/key-synchronization.md)
* [Example application](example/)
* [Setup enclave EC2 host](doc/setup.md)
