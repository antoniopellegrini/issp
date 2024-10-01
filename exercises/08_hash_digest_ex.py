# Refactor the hash digest exercise to use the Digest and DigestLayer classes from the issp module.

from cryptography.hazmat.primitives import hashes

from issp import Actor, Channel, Digest, DigestLayer


class SHA256(Digest):
    size = 32

    def compute(self, message: bytes) -> bytes:
        # Implement digest computation here.
        return b""


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=True)
    channel = Channel()
    alice_bob_layer = DigestLayer(channel, SHA256())

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    bob.receive(alice_bob_layer)

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    message = mallory.receive(channel)
    mallory.send(channel, message[7:])
    bob.receive(alice_bob_layer)

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    mallory_layer = DigestLayer(channel, SHA256())
    mallory.send(mallory_layer, b"#!%* you, Bob! - Alice")
    bob.receive(alice_bob_layer)


if __name__ == "__main__":
    main()
