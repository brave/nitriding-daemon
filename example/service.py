#!/usr/bin/env python3

import time
import requests

nitriding_url = "http://127.0.0.1:8080/enclave/ready"


def signal_ready():
    r = requests.get(url=nitriding_url)
    if r.status_code != requests.status_codes.codes.ok:
        raise Exception("Expected status code %d but got %d" %
                        (requests.status_codes.codes.ok, r.status_code))


def fetch_addr():
    r = requests.get(url="https://ifconfig.me/ip")
    print("[py] Our IP address is: %s" % r.text)


if __name__ == "__main__":
    signal_ready()
    print("[py] Signalled to nitriding that we're ready.")

    time.sleep(1)
    fetch_addr()
    print("[py] Made Web request to the outside world.")
