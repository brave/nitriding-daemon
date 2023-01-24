#!/bin/sh

/nitriding -fqdn example.com  -extport 8443  -intport 8080 &
echo "[sh] Started nitriding."

sleep 1

/service.py
echo "[sh] Ran Python script."
