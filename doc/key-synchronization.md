# Enclave key synchronization

Nitriding supports horizontal scaling, i.e., it allows for the synchronization
of key material among enclaves.  Key material consists of both nitriding and
application keys:

1. Nitriding's key material is the self-signed HTTPS certificate (both public
   and private key) that provides the confidential channel between clients and
   the enclave.
2. The application's key material is application-specific.  Nitriding is
   agnostic to the structure of this key material and treats it as arbitrary
   bytes.

For enclave key synchronization to work, there must be a single leader
enclave and one or more worker enclaves.  The leader enclave's sole job is to
create key material and make itself available to synchronize this key material
with worker enclaves.

To enable horizontal scaling, use the `-fqdn-leader` command line flag.

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
worker-->>-leader: OK (Attestation(nonce_l, nonce_w, K_i))

leader->>leader: Verify & create attestation
leader->>+worker: POST /enclave/sync (Attestation(nonce_w, E(keys, K_i)))
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