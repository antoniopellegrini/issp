import os
import secrets
import string
import sys
import time
from abc import ABC, abstractmethod

from ._authentication import SHA256
from ._encryption import AES, BlockCipher
from ._util import byte_size, xor


class RNG[T: (int, bytes)](ABC):
    @abstractmethod
    def next_value(self) -> T:
        pass

    @abstractmethod
    def set_seed(self, seed: T) -> None:
        pass

    def _gen_int(self, first: int, size: int) -> bytes:
        array = bytearray(first.to_bytes(byte_size(first), sys.byteorder))

        while len(array) < size:
            val = self.next_value()
            array.extend(val.to_bytes(byte_size(val), sys.byteorder))

        return bytes(array[:size])

    def _gen_bytes(self, first: bytes, size: int) -> bytes:
        array = bytearray(first)
        while len(array) < size:
            array.extend(self.next_value())
        return bytes(array[:size])

    def generate(self, size: int) -> bytes:
        val = self.next_value()
        return self._gen_int(val, size) if isinstance(val, int) else self._gen_bytes(val, size)


class LCG(RNG[int]):
    def __init__(self, a: int = 16807, c: int = 0, m: int = 2**31 - 1) -> None:
        self._state = time.time_ns() % m
        self._a = a % m
        self._c = c % m
        self._m = m

    def next_value(self) -> int:
        self._state = (self._a * self._state + self._c) % self._m
        return self._state

    def set_seed(self, seed: int) -> None:
        self._state = seed % self._m


class CounterRNG(RNG[bytes]):
    def __init__(self, cipher: BlockCipher = None) -> None:
        self._counter = 0
        if cipher is None:
            cipher = AES()
            cipher.apply_padding = False
        self._cipher = cipher

    def next_value(self) -> bytes:
        self._counter += 1
        return self._cipher.encrypt(self._counter.to_bytes(self._cipher.block_size))

    def set_seed(self, seed: bytes) -> None:
        self._cipher.key = seed


class ANSIx917(RNG[bytes]):
    def __init__(self, cipher: BlockCipher = None) -> None:
        if cipher is None:
            cipher = AES()
            cipher.apply_padding = False
        self._cipher = cipher
        self._state = self._cipher.encrypt(os.urandom(self._cipher.block_size))

    def next_value(self) -> bytes:
        temp = self._cipher.encrypt(time.time_ns().to_bytes(self._cipher.block_size))
        output = self._cipher.encrypt(xor(self._state, temp))
        self._state = self._cipher.encrypt(xor(output, temp))
        return output

    def set_seed(self, seed: bytes) -> None:
        self._cipher.key = seed


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


class Fortuna(RNG[bytes]):
    def __init__(self, sources: int = 5, pools: int = 5, reseed_length: int = 120) -> None:
        self._sources = [EntropySource(2**i) for i in range(sources)]
        self._pools = [EntropyPool() for _ in range(pools)]
        self._cipher = AES()
        self._cipher.apply_padding = False
        self._hash = SHA256()
        self._reseed_length = reseed_length
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
                entropy.extend(pool.get_entropy())
        return entropy

    def _reseed(self) -> None:
        self._reseed_count += 1
        entropy = self._get_entropy()
        key = self._hash.compute_code(self._cipher.key + self._hash.compute_code(entropy))
        self.set_seed(key)

    def set_seed(self, seed: bytes) -> None:
        self._cipher.key = seed

    def next_value(self) -> bytes:
        self._accumulate_entropy()

        if len(self._pools[0]) >= self._reseed_length:
            self._reseed()

        self._count += 1
        return self._cipher.encrypt(self._count.to_bytes(self._cipher.block_size))


class TRNG(RNG[bytes]):
    def next_value(self) -> bytes:
        return os.urandom(1)

    def set_seed(self, seed: bytes) -> None:
        del seed  # Unused

    def generate(self, size: int) -> bytes:
        return os.urandom(size)


def random_string(
    length: int,
    charset: str = string.printable,
) -> str:
    return "".join(secrets.choice(charset) for _ in range(length))


def random_int(
    min_value: int = 0,
    max_value: int = 2**32 - 1,
) -> int:
    return secrets.randbelow(max_value - min_value + 1) + min_value
