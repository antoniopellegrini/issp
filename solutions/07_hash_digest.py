# Verify the integrity of messages exchanged between Alice and Bob using SHA256 hash digests.
#
# Hint: Have a look at the cryprography.hazmat.primitives.hashes module.
# Docs: https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes

from cryptography.hazmat.primitives import hashes

from issp import Actor, Channel, log


def compute_digest(message: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    return digest.finalize()


def check_digest(message: bytes) -> None:
    hash_func = hashes.SHA256()

    # Split the message into the actual message and the digest.
    received_digest = message[-hash_func.digest_size :]
    message = message[: -hash_func.digest_size]

    # Compute the digest of the message.
    computed_digest = compute_digest(message)

    # Verify the digest.
    if received_digest == computed_digest:
        log.info("Digest verification succeeded.")
    else:
        log.warning("The message has been tampered with.")


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=True)
    channel = Channel()

    message = b"Hello, Bob! - Alice"
    message = message + compute_digest(message)
    alice.send(channel, message)
    mallory.receive(channel)
    check_digest(bob.receive(channel))

    message = b"Hello, Bob! - Alice"
    message = message + compute_digest(message)
    alice.send(channel, message)
    message = mallory.receive(channel)
    mallory.send(channel, message[7:])
    check_digest(bob.receive(channel))

    message = b"Hello, Bob! - Alice"
    message = message + compute_digest(message)
    alice.send(channel, message)
    mallory.receive(channel)
    message = b"#!%* you, Bob! - Alice"
    message = message + compute_digest(message)
    mallory.send(channel, message)
    check_digest(bob.receive(channel))


if __name__ == "__main__":
    main()
