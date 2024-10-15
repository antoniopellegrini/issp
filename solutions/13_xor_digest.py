# Verify the integrity of messages exchanged between Alice and Bob using 8 bytes XOR hash digests.
#
# Hint: you can use the xor and zero_pad functions from the issp module.

from issp import Actor, AuthenticationLayer, Authenticator, Channel, xor, zero_pad


class XOR(Authenticator):
    def compute_code(self, message: bytes) -> bytes:
        size = 8
        message = zero_pad(message, size)
        digest = bytes(size)
        for i in range(0, len(message), size):
            digest = xor(digest, message[i : i + size])
        return digest


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=True)
    channel = Channel()
    alice_bob_layer = AuthenticationLayer(channel, XOR())

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    bob.receive(alice_bob_layer)

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    message = mallory.receive(channel)
    mallory.send(channel, message[7:])
    bob.receive(alice_bob_layer)

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    mallory_layer = AuthenticationLayer(channel, XOR())
    mallory.send(mallory_layer, b"#!%* you, Bob! - Alice")
    bob.receive(alice_bob_layer)


if __name__ == "__main__":
    main()
