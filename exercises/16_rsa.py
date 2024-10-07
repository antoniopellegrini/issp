# Encrypt the communication between Alice and Bob using the RSA asymmetric cipher.
#
# Hint: Have a look at the cryprography.hazmat.primitives.asymmetric module.
# Docs: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa


from issp import Actor, Channel


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    alice.send(channel, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    bob.receive(channel)


if __name__ == "__main__":
    main()
