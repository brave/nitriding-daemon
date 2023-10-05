#!/bin/bash

source "$(dirname $0)/config.sh"

curl --request GET \
     --include \
     "http://localhost:${int_port}/enclave/state"
