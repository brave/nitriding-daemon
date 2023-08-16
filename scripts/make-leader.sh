#!/bin/bash

source "$(dirname $0)/config.sh"

curl --insecure \
     --include \
     "https://localhost:${ext_priv_port}/enclave/leader"