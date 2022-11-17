Nitriding example
=================

This directory contains an example application; a lightweight
[Python script](service.py)
that retrieves its IP address from an HTTP server.  The project's
[Dockerfile](Dockerfile) adds the nitriding standalone executable along with the
enclave application, consisting of the
[Python script](service.py)
and a
[shell script](start.sh)
that invokes nitriding in the background, followed by running the Python script.

To build the nitriding executable, the Docker image, the enclave image, and
finally run the enclave image, simply run:

    make
