#!/bin/bash

if [ $# -ne 1 ]
then
	echo >&2 "Usage: $0 IMAGE_EIF"
	exit 1
fi
image_eif="$1"

# gvproxy is the untrusted proxy application that runs on the EC2 host.  It
# acts as the bridge between the Internet and the enclave.  The code is
# available here:
# https://github.com/brave-intl/bat-go/tree/master/nitro-shim/tools/gvproxy
echo "[ec2] Starting gvproxy."
sudo gvproxy -listen vsock://:1024 &
pid="$!"

# Run enclave in debug mode and attach console, to see what's going on
# inside.  Note that this disables remote attestation.
echo "[ec2] Starting enclave."
nitro-cli run-enclave \
	--cpu-count 2 \
	--memory 600 \
	--enclave-cid 4 \
	--eif-path "$image_eif" \
	--debug-mode \
	--attach-console

echo "[ec2] Stopping gvproxy."
sudo kill -INT "$pid"
