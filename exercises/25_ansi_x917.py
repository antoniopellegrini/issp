# Implement a variation of the ANSI X9.17 PRNG using AES as the underlying block cipher,
# and use it to generate a key to encrypt the messages between Alice and Bob.
#
# Hint: Avoiding padding is particularly important in this case to preserve the
#       size of the internal state of the PRNG.


from issp import AES, RNG, Actor, Channel, EncryptionLayer, log


class ANSIx917(RNG):
    def set_seed(self, seed: bytes) -> None:
        # Implement.
        pass

    def next_value(self) -> bytes:
        # Implement.
        pass


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")

    channel = Channel()
    rng = ANSIx917()
    key = rng.generate(32)
    log.info("Key: %s", key)
    alice_bob_layer = EncryptionLayer(channel, AES(key))

    alice.send(alice_bob_layer, b"Hello, Bob! - Alice")
    bob.receive(alice_bob_layer)


if __name__ == "__main__":
    main()
