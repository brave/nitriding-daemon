# Key synchronization test scripts

This directory contains scripts that help with testing key synchronization
outside the context of Nitro Enclaves.  The scripts assume that we have at least
two "enclaves" that run on separate IP addresses.

First, change the `leader` variable inside config.sh to match the IP address of
your local leader "enclave".

To start the leader "enclave", run on machine A:

    ./launch-enclave.sh

To designate this "enclave" as the leader, run on machine A:

    ./make-leader.sh

To start a worker "enclave", run on machine B:

    ./launch-enclave.sh

To update the leader's key material, run on machine A:

    ./update-app-keys.sh