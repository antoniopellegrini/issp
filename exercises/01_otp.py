# Encrypt the communication between Alice and Bob using the OTP algorithm.
#
# Hint: Use the os.urandom function to generate a random key.

import os

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
