# Encrypt the communication between Alice and Bob using a digital envelope that uses
# AES to encrypt the message, and RSA to encrypt the symmetric key.
#
# Note: You may use the AES class from the issp library. You must implement RSA encryption
# using the cryptography library only.

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from issp import (
    AES,
    Actor,
    Channel,
    log,
)


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    # Bob generates a public/private key pair. The public key is shared with all participants.
    # Note: for RSA, the key size is equal to the size of encrypted messages.
    key_size = 2048
    bob_private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    bob_public_key = bob_private_key.public_key()
    rsa_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    message_cipher = AES()

    # Alice encrypts the message using a symmetric cipher.
    message = b"Hello, Bob! - Alice"
    iv = os.urandom(message_cipher.iv_size)
    encrypted_message = message_cipher.encrypt(message, iv)

    # Alice encrypt the symmetric key using an asymmetric cipher.
    encrypted_key = bob_public_key.encrypt(message_cipher.key, rsa_padding)

    # Alice sends the encrypted message, key, and iv.
    alice.send(channel, iv + encrypted_key + encrypted_message)
    mallory.receive(channel)

    # Bob splits the message into iv, key, and message.
    message = bob.receive(channel)
    iv = message[: message_cipher.iv_size]
    message = message[message_cipher.iv_size :]
    encrypted_key = message[: key_size // 8]
    message = message[key_size // 8 :]

    # Bob decrypts the symmetric key.
    key = bob_private_key.decrypt(encrypted_key, rsa_padding)

    # Bob decrypts the message using the symmetric key.
    message_cipher.key = key
    message = message_cipher.decrypt(message, iv)
    log.info("Bob received: %s", message)


if __name__ == "__main__":
    main()
