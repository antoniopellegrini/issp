# Verify the authenticity and integrity of messages exchanged between Alice and Bob using
# the HMAC algorithm with SHA256 as the underlying hash function.
#
# Hint: Have a look at the cryprography.hazmat.primitives.hmac module.
# Docs: https://cryptography.io/en/latest/hazmat/primitives/mac/hmac

import os

from cryptography.hazmat.primitives import hashes, hmac

from issp import Actor, Channel, Digest, DigestLayer


class HMAC(Digest):
    def __init__(self, key: bytes) -> None:
        self._key = key

    def compute(self, message: bytes) -> bytes:
        # Implement.
        return b""


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()
    alice_bob_layer = DigestLayer(channel, HMAC(os.urandom(32)))

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    bob.receive(alice_bob_layer)

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    message = mallory.receive(channel)
    mallory.send(channel, message[7:])
    bob.receive(alice_bob_layer)

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    mallory_layer = DigestLayer(channel, HMAC(os.urandom(32)))
    mallory.send(mallory_layer, b"#!%* you, Bob! - Alice")
    bob.receive(alice_bob_layer)


if __name__ == "__main__":
    main()
