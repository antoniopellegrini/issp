# Verify the integrity of messages exchanged between Alice and Bob using SHA256 hash digests.
#
# Hint: Have a look at the cryprography.hazmat.primitives.hashes module.
# Docs: https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes


from issp import Actor, Channel


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=True)
    channel = Channel()

    message = b"Hello, Bob! - Alice"
    # Compute and append the digest of the message.
    alice.send(channel, message)
    mallory.receive(channel)
    received = bob.receive(channel)
    # Verify the digest of the received message.

    message = b"Hello, Bob! - Alice"
    # Compute and append the digest of the message.
    alice.send(channel, message)
    message = mallory.receive(channel)
    mallory.send(channel, message[7:])
    # Verify the digest of the received message.

    message = b"Hello, Bob! - Alice"
    # Compute and append the digest of the message.
    alice.send(channel, message)
    mallory.receive(channel)
    message = b"#!%* you, Bob! - Alice"
    # Compute and append the digest of the message.
    mallory.send(channel, message)
    # Verify the digest of the received message.


if __name__ == "__main__":
    main()
