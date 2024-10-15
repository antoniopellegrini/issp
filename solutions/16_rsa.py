# Encrypt the communication between Alice and Bob using the RSA asymmetric cipher.
#
# Hint: Have a look at the cryprography.hazmat.primitives.asymmetric module.
# Docs: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from issp import Actor, Channel, log


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    # Vanilla RSA is vulnerable to multiple types of attacks,
    # which is why specially crafted padding schemes are used in all practical applications.
    rsa_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

    # Bob generates a public/private key pair. The public key is shared with all participants.
    bob_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bob_public_key = bob_private_key.public_key()

    # Alice encrypts the message using Bob's public key.
    alice.send(channel, bob_public_key.encrypt(b"Hello, Bob! - Alice", rsa_padding))
    mallory.receive(channel)
    received_message = bob.receive(channel)

    # Bob decrypts the message using his private key.
    log.info("Bob received: %s", bob_private_key.decrypt(received_message, rsa_padding))


if __name__ == "__main__":
    main()
