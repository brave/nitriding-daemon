# Enclave key synchronization

Nitriding supports horizontal scaling, i.e., it allows for the synchronization
of key material among identical enclaves.  Key material consists of both
_nitriding_ and _application_ keys:

1. Nitriding's key material is the self-signed HTTPS certificate (both public
   and private key) that provides the confidential channel between clients and
   the enclave.
2. The application's key material is application-specific.  Nitriding is
   agnostic to the structure of this key material and treats it as arbitrary
   bytes.

All of the above must be synced among enclaves.

For enclave key synchronization to work, there must be a _single leader
enclave_ and _one or more worker enclaves_.  The leader's sole job is to
create key material and make itself available for synchronizing this key
material with worker enclaves.  Worker enclaves do the actual work, i.e.,
process user requests.  Before doing any work though, workers must register
themselves with the leader, which triggers key synchronization.

To set up key synchronization, several steps are necessary:

* Use the `-fqdn-leader` command line flag on both the leader and the worker.
  Note that the leader and worker images _must be identical_.  The leader is
  only willing to synchronize key material with _identical enclaves_.
* Practically speaking, the leader is meant to run in a separate k8s deployment
  from the workers.

## Protocol

1. The leader creates a 20-byte nonce $\textrm{nonce}_l$ and sends it to the
   worker as part of a `GET` request.
2. Upon receiving $\textrm{nonce}_l$, the worker creates its own 20-byte nonce
   $\textrm{nonce}_w$ and an ephemeral asymmetric key pair $K_e = \(sk, pk\)$,
   which we generate with Go's `crypto/nacl/box` package. The worker now asks
   its hypervisor to create an attestation document $A_w$ containing
   $\textrm{nonce}_l$, $\textrm{nonce}_w$, and $pk$. The worker responds to the
   leader's `GET` request with $A_w$.
3. Having received $A_w$, the leader now verifies that...
   1. ...the attestation document is signed by the AWS Nitro Enclave hypervisor.
      This stops attackers from sending spoofed attestation documents.
   2. ...the attestation document contains $\textrm{nonce}_l$. This stops
      attackers from replaying old attestation documents.
   3. ...the attestation document's platform configuration registers are
      identical to the leader's registers. This stops attackers from using
      modified enclaves to extract the sensitive key material.
4. The leader is now convinced that it's dealing with an authentic worker
   enclave. In the next and final interaction, the leader encrypts its sensitive
   enclave keys $K_s$ using the worker's ephemeral public key $pk$, resulting in
   $E = \textrm{Enc}(K_s, pk)$. The leader then asks its hypervisor to create an
   attestation document $A_l$ containing $\textrm{nonce}_w$ and $E$. The leader
   sends $A_l$ to the worker in a separate `POST` request.
6. Upon receiving $A_l$, the worker first verifies the attestation document
   (same as above), and decrypts $E$ using $sk$, revealing in $K_s$, the
   sensitive enclave keys. At this point, key synchronization is complete.
7. After key synchronization, workers send a periodic heartbeat to the leader in
   a `POST` request.  The request's body contains a Base64-encoded SHA-256 hash
   over $K_s$.  This allows the leader to verify if the worker's keys are still
   up-to-date.  If not, the leader initiates key-synchronization using the
   protocol as above.

## Security considerations

The sensitive key material $K_s$ is protected as follows:

* Communication between leader and worker enclaves happens over AWS's Virtual
  Private Cloud (VPC).  We therefore expose the endpoints for key
  synchronization over a separate Web server that's not reachable over the
  Internet.

* Leader and worker enclaves use HTTPS as an underlying secure channel.  Note
  that the authenticity of our HTTPS certificates is rooted in the
  hypervisor-signed attestation documents; not in a certificate authority.

* Worker enclaves create an ephemeral key pair that's used to encrypt key
  material using Go's `crypto/nacl/box` API.  Even if an attacker can snoop on
  the VPC network _and_ compromise the confidentiality of our HTTPS connection,
  enclave keys are still protected by this ephemeral key pair.

```mermaid
sequenceDiagram
  box rgba(100, 100, 100, .1) Leader enclave
  participant leaderApp as Enclave application
  participant leader as Leader enclave
  end
  participant leaderEC2 as Leader EC2
  participant workerEC2 as Worker EC2
  box rgba(100, 100, 100, .1) Worker enclave
  participant worker as Worker enclave
  participant workerApp as Enclave application
  end

leader->>leader: Generate HTTPS certificate
leaderApp->>leaderApp: Generate key material

Note over leader,leaderEC2: Designating enclave as leader
leaderEC2->>+leader: GET /enclave/leader
leader->>leader: Expose leader-specific endpoints
leader-->>-leaderEC2: OK

Note over leaderApp,leader: Application sets its key material
leaderApp->>+leader: PUT /enclave/state (key material)
leader->>leader: Save key material
leader-->>-leaderApp: OK

Note over leader,worker: Worker announces itself to leader
worker->>+leader: POST /enclave/heartbeat
leader->>leader: Register new worker
leader-->>-worker: OK

Note over leader,worker: Leader initiates key synchronization
leader->>leader: Create nonce
leader->>+worker: GET /enclave/sync (nonce_l)
worker->>worker: Create attestation, nonce, and ephemeral keys
worker-->>-leader: OK (Attestation(nonce_l, nonce_w, pk))

leader->>leader: Verify & create attestation
leader->>+worker: POST /enclave/sync (Attestation(nonce_w, E(keys, pk)))
worker->>worker: Verify attestation & install keys
worker-->>-leader: OK

Note over worker,workerApp: Application retrieves key material
workerApp->>+worker: GET /enclave/state
worker->>worker: Retrieve key material
worker-->>-workerApp: OK (key material)
workerApp->>workerApp: Install key material

Note over leader, worker: Worker starts heartbeat loop

loop Heartbeat
  worker->>+leader: POST /enclave/heartbeat (Hash(key material))
  leader-->>-worker: OK
end

Note over leaderApp: Application updates its key material
leaderApp->>+leader: PUT /enclave/state (key material)
leader->>leader: Save key material
leader-->>-leaderApp: OK

note over leader,worker: Leader initiates key re-synchronization as above
```