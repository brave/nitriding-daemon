#!/usr/bin/env python3

import time
import urllib.request

nitriding_url = "http://127.0.0.1:8080/enclave/ready"


def signal_ready():
    r = urllib.request.urlopen(nitriding_url)
    if r.getcode() != 200:
        raise Exception("Expected status code %d but got %d" %
                        (requests.status_codes.codes.ok, r.status_code))


def fetch_addr():
    url = "https://raw.githubusercontent.com/brave/nitriding-daemon/master/README.md"
    with urllib.request.urlopen(url) as f:
        print("[py] Fetched %d bytes of README.md." % len(f.read(100)))


if __name__ == "__main__":
    signal_ready()
    print("[py] Signalled to nitriding that we're ready.")

    time.sleep(1)
    fetch_addr()
    print("[py] Made Web request to the outside world.")
