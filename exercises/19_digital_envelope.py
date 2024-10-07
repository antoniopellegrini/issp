# Encrypt the communication between Alice and Bob using a digital envelope that uses
# AES to encrypt the message, and RSA to encrypt the symmetric key.
#
# Note: You may use the AES class from the issp library. You must implement RSA encryption
# using the cryptography library only.


from issp import (
    Actor,
    Channel,
)


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
