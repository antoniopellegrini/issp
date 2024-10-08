# Help Mallory perform a brute-force attack on the MAC key used by Alice and Bob.
#
# Hint: Have a look at the itertools.product function.

import os
from itertools import product

from issp import HMAC, Actor, AuthenticationLayer, Channel, log


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=True)
    channel = Channel()

    key = bytes(30) + os.urandom(2)
    digest = HMAC(key)
    alice_bob_layer = AuthenticationLayer(channel, digest)

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")

    message = mallory.receive(channel)
    mac = message[-digest.code_size :]
    message = message[: -digest.code_size]

    for byte_tuple in product(range(256), repeat=digest.code_size):
        found_key = bytes(byte_tuple)
        if HMAC(found_key).verify(message, mac):
            break

    log.info("Original key: %s", key)
    log.info("Key found by Mallory: %s", found_key)

    mallory_layer = AuthenticationLayer(channel, HMAC(found_key))
    mallory.send(mallory_layer, b"#!%* you, Bob! - Alice")

    bob.receive(alice_bob_layer)


if __name__ == "__main__":
    main()
