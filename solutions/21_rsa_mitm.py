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

    # Mallory intercepts the message and sends his public key to Alice.
    mallory_bob_public_key = serialization.load_pem_public_key(mallory.receive(channel))
    mallory_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    message = mallory_private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    mallory.send(channel, message)

    # Alice receives Mallory's public key, thinking it's Bob's, and uses it to encrypt a message.
    alice_bob_public_key = serialization.load_pem_public_key(alice.receive(channel))
    alice.send(channel, alice_bob_public_key.encrypt(b"Hello, Bob! - Alice", rsa_padding))

    # Mallory can now eavesdrop on the messages between Alice and Bob.
    message = mallory.receive(channel)
    log.info("Mallory decrypted: %s", mallory_private_key.decrypt(message, rsa_padding))

    # And he can also tamper with the communication.
    mallory.send(channel, mallory_bob_public_key.encrypt(b"#!%* you, Bob! - Alice", rsa_padding))

    # Bob receives Mallory's message and decrypts it, thinking it's from Alice.
    message = bob.receive(channel)
    log.info("Bob decrypted: %s", bob_private_key.decrypt(message, rsa_padding))


if __name__ == "__main__":
    main()
