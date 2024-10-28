# Implement a variation of the Fortuna PRNG with the following characteristics:
#
# - It should have 5 entropy sources and 5 entropy pools.
# - The 5 entropy sources should provide 1, 2, 4, 8, and 16 bytes of entropy, respectively.
# - It should reseed every time the first pool has at least 240 bytes of entropy.
# - You don't need to manage the seed file.

import os
import time

from issp import AES, RNG, SHA256, Actor, Channel, EncryptionLayer, log


class EntropySource:
    def __init__(self, entropy_bytes: int) -> None:
        self._entropy_bytes = entropy_bytes

    def get_entropy(self) -> bytes:
        return os.urandom(self._entropy_bytes)


class EntropyPool:
    def __init__(self, initial_entropy_bytes: int = 8) -> None:
        initial_entropy = os.urandom(initial_entropy_bytes) if initial_entropy_bytes else b""
        self._deskewer = SHA256()
        self._pool = bytearray(initial_entropy)

    def __len__(self) -> int:
        return len(self._pool)

    def add_entropy(self, entropy: bytes) -> None:
        self._pool.extend(entropy)

    def get_entropy(self) -> bytes:
        entropy = self._deskewer.compute_code(self._pool)
        self._pool.clear()
        return entropy


class Fortuna(RNG):
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
    rng = Fortuna()
    cipher = AES()
    enc_layer = EncryptionLayer(channel, cipher)

    for i in range(128):
        time.sleep(1.0)
        cipher.key = rng.generate(cipher.key_size)
        log.info("Key: %s", cipher.key)
        message = f"{i}. Hello, Bob! - Alice"
        alice.send(enc_layer, message.encode())
        bob.receive(enc_layer)


if __name__ == "__main__":
    main()
