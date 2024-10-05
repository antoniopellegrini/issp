# Refactor the AES exercise to use the SymmetricCipher and EncryptionLayer classes
# from the issp module.

import os

from issp import Actor, Channel, EncryptionLayer, SymmetricCipher


class AES(SymmetricCipher):
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
    alice_bob_layer = EncryptionLayer(channel, AES(os.urandom(32)))

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    bob.receive(alice_bob_layer)


if __name__ == "__main__":
    main()
