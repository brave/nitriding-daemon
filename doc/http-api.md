# Nitriding's HTTP API

## External endpoints, reachable to the Internet

* `GET /enclave` Returns an index page explaining that this code runs
  inside an enclave.  
  The enclave responds with status code `200 OK`.

* `GET /enclave/attestation?nonce={nonce}` Returns an attestation document
  containing the given nonce.  
  `nonce` must be a 20-byte nonce encoded in 40 hexadecimal digits.
  The attestation document is encoded using Base64.
  If all goes well, the enclave responds with status code `200 OK`.

* `GET /enclave/config` Returns nitriding's configuration.  
  The enclave responds with status code `200 OK`.

* `GET /enclave/debug` If enabled, returns profiling information.  
  If nitriding is invoked with the `-debug` command line flag,
  it exposes this endpoint to make profiling information available.
  If all goes well, the enclave responds with status code `200 OK`.

## External endpoints, reachable to other enclaves

* `GET /enclave/sync?nonce={nonce}` Exposed by workers, the leader talks to this endpoint to initiate key synchronization.  
  `nonce` must be a 20-byte nonce encoded in 40 hexadecimal digits.
  If all goes well, the worker responds with status code `200 OK` and the following JSON-formatted body:
  ```
  {
    "document": "{Base64-encoded attestation document}",
  }
  ```

* `POST /enclave/sync` Exposed by workers, the leader talks to this endpoint to
  complete key synchronization.  

  The request must contain the following JSON-formatted body:
  ```
  {
    "document": "{Base64-encoded attestation document}",
    "encrypted_keys": "{Base64-encoded, encrypted enclave keys}",
  }
  ```
  If all goes well, the worker responds with status code `200 OK`.

* `POST /enclave/heartbeat` Exposed by the leader, workers periodically send a heartbeat to this endpoint.  
  The request must contain the following JSON-formatted body:
  ```
  {
    "hashed_keys": "{hashed_keys}",
    "worker_hostname": "{worker_hostname}",
  }
  ```
  `worker_hostname` contains the worker's EC2-internal hostname, e.g., `ip-12-34-56-78.us-east-2.compute.internal`.  
  `hashed_keys` contains the Base64-encoded SHA-256 hash over the worker's enclave key material.
  If all goes well, the leader responds with status code `200 OK`.

* `GET /enclave/leader?nonce={nonce}` Exposed by all enclaves, this endpoint
  helps enclaves figure out who the leader is.  
  `nonce` must be a 20-byte nonce encoded in 40 hexadecimal digits.
  All enclaves create a random `nonce` and send it to the leader's endpoint.
  If the leader notices that it's talking to itself (by comparing the received nonce to its previously-generated nonce),
  it designates itself as the leader.
  After that, the leader responds with status code `410 Gone`.
  Workers know that they are workers when they receive status code `410 Gone`.
  Before that, the leader responds with status code `200 OK`.
  While workers expose this endpoint too, they should never receive any requests.

## Internal endpoints, reachable to the application

* `GET /enclave/ready` Used by the enclave application to signal its readiness.  
  When nitriding is invoked with the command line argument `-wait-for-app`,
  it refrains from starting its external Web servers until the application
  signals its readiness by calling this endpoint, after which nitriding starts
  the external Web servers.
  The first invocation of this endpoint returns status code `200 OK`.
  Subsequent invocations return status code `410 Gone`.

* `GET /enclave/state` Returns the application's state in the response body.  
  This endpoint allows an application to retrieve state
  (e.g., confidential key material) that was previously set by the "leader" application.
  If synchronization is not enabled via the `-fqdn-leader` command line
  argument, the endpoint responds with status code `403 Forbidden`.
  If synchronization is enabled but leader designation is currently in progress,
  the endpoint responds with status code `503 Service Unavailable`.
  If synchronization is enabled and the enclave is the leader,
  the endpoint responds with status code `410 Gone`.
  Finally, if synchronization is enabled _and_ the enclave is a worker,
  the endpoint returns the application's state in the response body and
  responds with status code `200 OK`.
  The application's state is returned without encoding,
  using the `application/octet-stream` content type.

* `PUT /enclave/state` Sets the application's state.  
  This endpoint allows the "leader" application to set state that is
  subsequently synchronized with worker enclaves.
  If synchronization is not enabled via the `-fqdn-leader` command line
  argument, the endpoint responds with status code `403 Forbidden`.
  If synchronization is enabled but leader designation is currently in progress,
  the endpoint responds with status code `503 Service Unavailable`.
  If synchronization is enabled and the enclave is a worker,
  the endpoint responds with status code `410 Gone`.
  Finally, if synchronization is enabled _and_ the enclave is the leader,
  the endpoint saves the state that's set in the request body and
  responds with status code `200 OK`.

* `POST /enclave/hash` Allows the application to set a hash that's included in
  attestation documents.  
  The enclave application can invoke this endpoint to submit a SHA-256 hash that
  nitriding is subsequently going to include in attestation documents.
  The Base64-encoded SHA-256 hash must be given in the request body.
  If all goes well, the endpoint responds with status code `200 OK`.