#!/bin/sh

nitriding -fqdn example.com -ext-pub-port 443 -intport 8080 -wait-for-app &
echo "[sh] Started nitriding."

sleep 1

service.py
echo "[sh] Ran Python script."
