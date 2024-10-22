# Implement the Diffie-Hellman key exchange scheme.
#
# Hint: Have a look at the cryprography.hazmat.primitives.asymmetric module.
# Docs: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dh


from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from issp import AES, Actor, Channel, EncryptionLayer, log


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    channel = Channel()

    # Alice and Bob agree on some parameters and generate their private keys.
    # Note: The key size is kept small to speed up parameter generation.
    #       In practice, a key size of 2048 bits or more should be used.
    log.info("Generating parameters...")
    parameters = dh.generate_parameters(generator=2, key_size=1024)

    log.info("Generating private keys...")
    alice_private_key = parameters.generate_private_key()
    bob_private_key = parameters.generate_private_key()

    # Alice sends her public key to Bob.
    message = alice_private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    alice.send(channel, message)

    # Bob receives Alice's public key and generates his shared key.
    bob_alice_public_key = serialization.load_pem_public_key(bob.receive(channel))
    bob_alice_shared_key = bob_private_key.exchange(bob_alice_public_key)

    # Bob sends his public key to Alice.
    message = bob_private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    bob.send(channel, message)

    # Alice receives Bob's public key and generates her shared key.
    alice_bob_public_key = serialization.load_pem_public_key(alice.receive(channel))
    alice_bob_shared_key = alice_private_key.exchange(alice_bob_public_key)

    # Alice and Bob now have the same shared key.
    if alice_bob_shared_key == bob_alice_shared_key:
        log.info("Alice and Bob have the same shared key: %s", alice_bob_shared_key)
    else:
        err_msg = "Alice and Bob do not have the same shared key"
        raise AssertionError(err_msg)

    # The shared key is too long for AES, so we derive a shorter key from it.
    key_derivator = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=None)
    alice_bob_shared_key = key_derivator.derive(alice_bob_shared_key)

    key_derivator = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=None)
    bob_alice_shared_key = key_derivator.derive(bob_alice_shared_key)

    # Alice and Bob can now communicate securely.
    alice_bob_channel = EncryptionLayer(channel, AES(alice_bob_shared_key))
    bob_alice_channel = EncryptionLayer(channel, AES(bob_alice_shared_key))

    alice.send(alice_bob_channel, b"Hello, Bob! - Alice")
    bob.receive(bob_alice_channel)


if __name__ == "__main__":
    main()
