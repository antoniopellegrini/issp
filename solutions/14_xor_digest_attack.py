# Help Mallory perform two attacks on the encrypted XOR hash scheme used by Alice and Bob:
#
# 1. Corrupt the message sent by Alice to Bob by scrambling the bytes, but keeping the MAC intact.
# 2. Forge a message from Alice to Bob, again keeping the MAC intact.

import os

from issp import AES, XOR, Actor, AuthenticationLayer, Channel, EncryptedHashMAC, xor, zero_pad


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    xor_digest = XOR()
    mac = EncryptedHashMAC(xor_digest, AES(os.urandom(32)))
    alice_bob_layer = AuthenticationLayer(channel, mac)

    # Attack 1.
    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    message = mallory.receive(channel)
    block_1 = message[0 : xor_digest.code_size]
    block_2 = message[xor_digest.code_size : 2 * xor_digest.code_size]
    remainder = message[2 * xor_digest.code_size :]
    message = block_2 + block_1 + remainder
    mallory.send(channel, message)
    bob.receive(alice_bob_layer)

    # Attack 2.
    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    message = mallory.receive(channel)

    new_message = zero_pad(b"#!%* you, Bob! - Alice", xor_digest.code_size)
    new_digest = xor_digest.compute_code(new_message)

    original_message = message[: -mac.code_size]
    original_mac = message[-mac.code_size :]
    original_digest = xor_digest.compute_code(original_message)

    new_message += xor(new_digest, original_digest)
    new_message += original_mac

    mallory.send(channel, new_message)
    bob.receive(alice_bob_layer)


if __name__ == "__main__":
    main()
