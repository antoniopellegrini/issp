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
    SOURCES = 5
    POOLS = 5
    RESEED_LENGTH = 240

    def __init__(self) -> None:
        self._sources = [EntropySource(2**i) for i in range(self.SOURCES)]
        self._pools = [EntropyPool() for _ in range(self.POOLS)]
        self._cipher = AES()
        self._cipher.apply_padding = False
        self._hash = SHA256()
        self._reseed_count = 0
        self._count = 0

    def _accumulate_entropy(self) -> None:
        for source in self._sources:
            for pool in self._pools:
                pool.add_entropy(source.get_entropy())

    def _get_entropy(self) -> bytes:
        entropy = bytearray()
        for i, pool in enumerate(self._pools):
            if self._reseed_count % (2**i) == 0:
                log.info("Using pool: %d (%d B)", i, len(pool))
                entropy.extend(pool.get_entropy())
        return entropy

    def _reseed(self) -> None:
        self._reseed_count += 1
        log.info("Reseed: %d", self._reseed_count)
        entropy = self._get_entropy()
        key = self._hash.compute_code(self._cipher.key + self._hash.compute_code(entropy))
        self.set_seed(key)

    def set_seed(self, seed: bytes) -> None:
        self._cipher.key = seed

    def next_value(self) -> bytes:
        self._accumulate_entropy()

        if len(self._pools[0]) >= self.RESEED_LENGTH:
            self._reseed()

        self._count += 1
        return self._cipher.encrypt(self._count.to_bytes(self._cipher.block_size))


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
