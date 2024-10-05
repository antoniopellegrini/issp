# Refactor the OTP exercise to use the SymmetricCipher and EncryptionLayer classes
# from the issp module.

import os

from issp import Actor, Channel, log


def xor(data: bytes, key: bytes) -> bytes:
    length = len(data)
    if length > len(key):
        err_msg = "Key is too short"
        raise ValueError(err_msg)
    return bytes(data[i] ^ key[i] for i in range(length))


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    key = os.urandom(256)
    message = b"Hello, Bob! - Alice"
    log.info("Alice wants to send: %s", message)
    message = xor(message, key)
    alice.send(channel, message)

    mallory.receive(channel)
    message = bob.receive(channel)
    message = xor(message, key)
    log.info("Bob decrypted: %s", message)


if __name__ == "__main__":
    main()
