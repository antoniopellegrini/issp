# Implement the Diffie-Hellman key exchange scheme.
#
# Hint: Have a look at the cryprography.hazmat.primitives.asymmetric module.
# Docs: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dh


from issp import AES, Actor, Channel, EncryptionLayer


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    channel = Channel()

    # Implement the key exchange here.
    alice_bob_shared_key = b""
    bob_alice_shared_key = b""

    # Alice and Bob can now communicate securely.
    alice_bob_channel = EncryptionLayer(channel, AES(alice_bob_shared_key))
    bob_alice_channel = EncryptionLayer(channel, AES(bob_alice_shared_key))

    alice.send(alice_bob_channel, b"Hello, Bob! - Alice")
    bob.receive(bob_alice_channel)


if __name__ == "__main__":
    main()
