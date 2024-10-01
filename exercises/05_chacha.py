# Encrypt the communication between Alice and Bob using the ChaCha20 stream cipher.
#
# Hint: Have a look at the cryprography.hazmat.primitives.ciphers module.
# Docs: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption

import os

from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import algorithms

from issp import Actor, Channel, Cipher, EncryptionLayer


class ChaCha(Cipher):
    iv_size = 16

    def encrypt(self, message: bytes, iv: bytes | None) -> bytes:
        # Implement encryption here.
        return message

    def decrypt(self, message: bytes, iv: bytes | None) -> bytes:
        # Implement decryption here.
        return message


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)

    channel = Channel()
    alice_bob_layer = EncryptionLayer(channel, ChaCha(os.urandom(32)))

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    bob.receive(alice_bob_layer)


if __name__ == "__main__":
    main()
