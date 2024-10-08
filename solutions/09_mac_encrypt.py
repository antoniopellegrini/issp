# Verify the authenticity and integrity of messages exchanged between Alice and Bob using
# SHA256 hash digests encrypted with AES in CBC mode.

import os

from issp import AES, SHA256, Actor, AuthenticationLayer, Authenticator, Channel


class SHA256AES(Authenticator):
    def __init__(self, key: bytes) -> None:
        self._aes = AES(key)
        self._sha = SHA256()

    def compute_code(self, message: bytes) -> bytes:
        iv = os.urandom(self._aes.iv_size)
        digest = self._sha.compute_code(message)
        # For the receiver to be able to decrypt it, the code must include the IV.
        return iv + self._aes.encrypt(digest, iv)

    def verify(self, message: bytes, fingerprint: bytes) -> bool:
        # Split the fingerprint into the IV and the encrypted fingerprint.
        iv_size = self._aes.iv_size
        iv = fingerprint[:iv_size]
        encrypted_fingerprint = fingerprint[iv_size:]
        # Decrypt the fingerprint and verify it.
        try:
            fingerprint = self._aes.decrypt(encrypted_fingerprint, iv)
        except ValueError:
            return False
        return self._sha.verify(message, fingerprint)


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
