# Fix the man-in-the-middle vulnerability by introducing public key certificates.
# Assume that there is a certificate authority (CA) known to all parties
# that can sign the certificates.
#
# Hint: The certificate should contain Bob's public key and his name.

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from issp import Actor, Channel, log


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    hash_func = hashes.SHA256()
    oaep_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hash_func),
        algorithm=hash_func,
        label=None,
    )
    pss_padding = padding.PSS(mgf=padding.MGF1(hash_func), salt_length=padding.PSS.MAX_LENGTH)

    # Certificate authority (CA) keys.
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_public_key = ca_private_key.public_key()

    # Bob prepares his CSR and submits it to the CA.
    bob_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bob_unsigned_certificate = (
        bob_private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        + bob.name.encode()
    )

    # The CA signs Bob's certificate.
    ca_signature = ca_private_key.sign(bob_unsigned_certificate, pss_padding, hash_func)
    bob_signed_certificate = bob_unsigned_certificate + ca_signature

    # Bob sends his signed certificate to Alice.
    bob.send(channel, bob_signed_certificate)
    mallory.receive(channel)

    # Alice receives Bob's certificate and verifies it with the CA's public key.
    certificate = alice.receive(channel)
    certificate_signature = certificate[-ca_public_key.key_size // 8 :]
    certificate = certificate[: -ca_public_key.key_size // 8]
    ca_public_key.verify(certificate_signature, certificate, pss_padding, hash_func)

    # Alice extracts Bob's public key from the certificate, and uses it to encrypt a message.
    alice_bob_public_key = serialization.load_pem_public_key(certificate)
    alice.send(channel, alice_bob_public_key.encrypt(b"Hello, Bob! - Alice", oaep_padding))
    mallory.receive(channel)

    # Bob receives Alice's message and decrypts it.
    received_message = bob.receive(channel)
    log.info("Bob decrypted: %s", bob_private_key.decrypt(received_message, oaep_padding))


if __name__ == "__main__":
    main()
