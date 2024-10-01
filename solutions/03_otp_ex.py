# Refactor the OTP exercise to use the Cipher and EncryptionLayer classes from the issp module.

import os

from issp import Actor, Channel, Cipher, EncryptionLayer


def xor(data: bytes, key: bytes) -> bytes:
    length = len(data)
    if length > len(key):
        err_msg = "Key is too short"
        raise ValueError(err_msg)
    return bytes(data[i] ^ key[i] for i in range(length))


class OTP(Cipher):
    def encrypt(self, data: bytes, iv: bytes | None) -> bytes:
        del iv  # Unused
        return xor(data, self.key)

    def decrypt(self, data: bytes, iv: bytes | None) -> bytes:
        del iv  # Unused
        return xor(data, self.key)


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)

    channel = Channel()
    alice_bob_layer = EncryptionLayer(channel, OTP(os.urandom(256)))

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    bob.receive(alice_bob_layer)


if __name__ == "__main__":
    main()
