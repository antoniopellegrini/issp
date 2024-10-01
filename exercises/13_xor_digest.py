# Verify the integrity of messages exchanged between Alice and Bob using 8 bytes XOR hash digests.

from issp import Actor, Channel, Digest, DigestLayer, xor, zero_pad


class XOR(Digest):
    def compute(self, message: bytes) -> bytes:
        # Implement
        return b""


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=True)
    channel = Channel()
    alice_bob_layer = DigestLayer(channel, XOR())

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    bob.receive(alice_bob_layer)

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    message = mallory.receive(channel)
    mallory.send(channel, message[7:])
    bob.receive(alice_bob_layer)

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    mallory_layer = DigestLayer(channel, XOR())
    mallory.send(mallory_layer, b"#!%* you, Bob! - Alice")
    bob.receive(alice_bob_layer)


if __name__ == "__main__":
    main()
