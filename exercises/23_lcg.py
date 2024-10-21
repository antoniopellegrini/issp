# Implement a simple Linear Congruential Generator (LCG) and use it to generate a key
# to encrypt the messages between Alice and Bob.


from issp import AES, RNG, Actor, Channel, EncryptionLayer, log


class LCG(RNG):
    def set_seed(self, seed: int) -> None:
        # Implement.
        pass

    def next_value(self) -> int:
        # Implement.
        pass


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")

    channel = Channel()
    rng = LCG()
    key = rng.generate(32)
    log.info("Key: %s", key)
    alice_bob_layer = EncryptionLayer(channel, AES(key))

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    bob.receive(alice_bob_layer)


if __name__ == "__main__":
    main()
