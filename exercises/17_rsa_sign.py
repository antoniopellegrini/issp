# Verify the authenticity, integrity, and non-repudiation of messages exchanged
# between Alice and Bob using RSA signatures.
#
# Hint: Have a look at the cryprography.hazmat.primitives.asymmetric module.
# Docs: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa


from issp import Actor, Channel


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    message = b"Hello, Bob! - Alice"

    # Sign the message here.

    alice.send(channel, message)

    # Uncomment the next line to let Mallory tamper with the message.
    # mallory.send(channel, mallory.receive(channel)[8:])

    received_message = bob.receive(channel)

    # Verify the signature here.


if __name__ == "__main__":
    main()
