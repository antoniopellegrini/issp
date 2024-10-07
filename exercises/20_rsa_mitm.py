# Help Mallory perform a successful man-in-the-middle attack on the encrypted communication
# between Alice and Bob. Mallory should be able to eavesdrop on the messages between Alice
# and Bob, and tamper with the communication.

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from issp import Actor, Channel, log


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    rsa_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

    bob_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Bob sends his public key to Alice.
    message = bob_private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    bob.send(channel, message)

    # Alice receives Bob's public key, and uses it to encrypt a message.
    alice_bob_public_key = serialization.load_pem_public_key(alice.receive(channel))
    alice.send(channel, alice_bob_public_key.encrypt(b"Hello, Bob! - Alice", rsa_padding))

    # Bob receives Alice's message and decrypts it.
    received_message = bob.receive(channel)
    log.info("Bob decrypted: %s", bob_private_key.decrypt(received_message, rsa_padding))


if __name__ == "__main__":
    main()
