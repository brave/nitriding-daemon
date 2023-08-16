# Key synchronization test scripts

This directory contains scripts that help with testing key synchronization
outside the context of Nitro Enclaves.  The scripts assume that we have at least
two "enclaves" that run on separate IP addresses.

To start the leader "enclave", run:

    ./launch-leader.sh

To designate this "enclave" as the leader, run:

    ./make-leader.sh

To start a worker "enclave", run:

    ./launch-worker.sh

To update the leader's key material, run:

    ./update-app-keys.sh