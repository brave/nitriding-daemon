#!/bin/bash

source "$(dirname $0)/config.sh"

curl --request PUT \
     --include \
     "http://localhost:${int_port}/enclave/state" --data 'NewAppKeys'