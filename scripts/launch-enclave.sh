#!/bin/bash

source "$(dirname $0)/config.sh"

nitriding-daemon \
    -debug \
    -fqdn localhost \
    -fqdn-leader "$leader" \
    -ext-pub-port "$ext_pub_port" \
    -ext-priv-port "$ext_priv_port" \
    -intport "$int_port"