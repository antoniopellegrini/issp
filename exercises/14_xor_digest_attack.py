# Help Mallory perform two attacks on the encrypted XOR hash scheme used by Alice and Bob:
#
# 1. Corrupt the message sent by Alice to Bob by scrambling the bytes, but keeping the MAC intact.
# 2. Forge a message from Alice to Bob, again keeping the MAC intact.

import os

from issp import AES, XOR, Actor, AuthenticationLayer, Channel, EncryptedHashMAC


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    xor_digest = XOR()
    digest = EncryptedHashMAC(xor_digest, AES(os.urandom(32)))
    alice_bob_layer = AuthenticationLayer(channel, digest)

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    # Attack 1.
    bob.receive(alice_bob_layer)

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    # Attack 2.
    bob.receive(alice_bob_layer)


if __name__ == "__main__":
    main()
