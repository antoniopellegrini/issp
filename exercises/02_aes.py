# Encrypt the communication between Alice and Bob using the AES block cipher in CBC mode.
#
# Hint: Have a look at the cryprography.hazmat.primitives.ciphers module.
# Docs: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption

import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from issp import Actor, Channel, log


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    message = b"Hello, Bob! - Alice"
    log.info("Alice wants to send: %s", message)

    # Encrypt the message here.

    alice.send(channel, message)

    mallory.receive(channel)
    message = bob.receive(channel)

    # Decrypt the message here.

    log.info("Bob decrypted: %s", message)


if __name__ == "__main__":
    main()
