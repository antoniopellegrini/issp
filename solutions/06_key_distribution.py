# Implement the symmetric key distribution scheme that we have discussed in the lectures.
#
# Hint: You can use the pre-implemented ciphers from the issp module (e.g. AES or ChaCha).

import os

from issp import AES, Actor, Channel, EncryptionLayer


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    kdc = Actor("KDC")
    channel = Channel()

    # We assume that Alice and Bob already have a shared secret with the KDC.
    alice_kdc_layer = EncryptionLayer(channel, AES())
    bob_kdc_layer = EncryptionLayer(channel, AES())

    # Alice sends a request to the KDC to talk to Bob.
    alice.send(alice_kdc_layer, b"Hello, KDC. I would like to talk to Bob.")
    mallory.receive(channel)
    kdc.receive(alice_kdc_layer)

    # The KDC generates a new key for Alice and Bob and sends it to them.
    new_key = os.urandom(32)
    kdc.send(alice_kdc_layer, new_key)
    mallory.receive(channel)
    alice_bob_key = alice.receive(alice_kdc_layer)
    kdc.send(bob_kdc_layer, new_key)
    mallory.receive(channel)
    bob_alice_key = bob.receive(bob_kdc_layer)

    # Alice and Bob can now communicate securely.
    alice_bob_layer = EncryptionLayer(channel, AES(alice_bob_key))
    bob_alice_layer = EncryptionLayer(channel, AES(bob_alice_key))
    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    bob.receive(bob_alice_layer)


if __name__ == "__main__":
    main()
