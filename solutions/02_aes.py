# Encrypt the communication between Alice and Bob using the AES block cipher in CBC mode.
#
# Hint: Have a look at the cryprography.hazmat.primitives.ciphers module.
# Docs: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption

import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from issp import Actor, Channel, log

BLOCK_SIZE = 128


def encrypt(message: bytes, key: bytes, iv: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    message = padder.update(message) + padder.finalize()
    return encryptor.update(message) + encryptor.finalize()


def decrypt(message: bytes, key: bytes, iv: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    message = decryptor.update(message) + decryptor.finalize()
    return unpadder.update(message) + unpadder.finalize()


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    key = os.urandom(32)
    iv_size = BLOCK_SIZE // 8
    iv = os.urandom(iv_size)

    message = b"Hello, Bob! - Alice"
    log.info("Alice wants to send: %s", message)

    # The initialization vector must be sent together with the encrypted message.
    message = iv + encrypt(message, key, iv)
    alice.send(channel, message)
    mallory.receive(channel)

    try:
        # Bob must first separate the initialization vector from the encrypted message.
        message = bob.receive(channel)
        iv = message[:iv_size]
        message = message[iv_size:]

        # Then he can decrypt the message.
        message = decrypt(message, key, iv)
    except ValueError:
        log.info("Bob received a corrupted message")
    else:
        log.info("Bob decrypted: %s", message)


if __name__ == "__main__":
    main()
