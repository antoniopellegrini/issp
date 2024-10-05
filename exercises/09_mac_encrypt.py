# Verify the authenticity and integrity of messages exchanged between Alice and Bob using
# SHA256 hash digests encrypted with AES in CBC mode.

import os

from issp import AES, SHA256, Actor, AuthenticationLayer, Authenticator, Channel


class SHA256AES(Authenticator):
    def __init__(self, key: bytes) -> None:
        self._aes = AES(key)
        self._sha = SHA256()

    def compute_code(self, message: bytes) -> bytes:
        # Implement.
        return b""

    def verify(self, message: bytes, code: bytes) -> bool:
        # The default implementation of the check method is insufficient.
        # We need to decrypt the code first, then perform the check.
        return False


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()
    alice_bob_layer = AuthenticationLayer(channel, SHA256AES(os.urandom(32)))

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    bob.receive(alice_bob_layer)

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    message = mallory.receive(channel)
    mallory.send(channel, message[7:])
    bob.receive(alice_bob_layer)

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    mallory_layer = AuthenticationLayer(channel, SHA256AES(os.urandom(32)))
    mallory.send(mallory_layer, b"#!%* you, Bob! - Alice")
    bob.receive(alice_bob_layer)


if __name__ == "__main__":
    main()
