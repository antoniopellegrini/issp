from __future__ import annotations

import os
from abc import ABC, abstractmethod
from functools import cached_property
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes

from ._util import xor, zero_pad

if TYPE_CHECKING:
    from ._comm import Layer
    from ._encryption import Cipher


class DigestLayer:
    def __init__(self, layer: Layer, digest: Digest) -> None:
        self._layer = layer
        self._digest = digest

    def send(self, message: bytes) -> None:
        fingerprint = self._digest.compute(message)
        self._layer.send(message + fingerprint)

    def receive(self) -> bytes | None:
        if not (message := self._layer.receive()):
            return None

        fingerprint = message[-self._digest.size :]
        message = message[: -self._digest.size]

        if self._digest.check(message, fingerprint):
            return message

        err_msg = "The message is not authentic"
        raise ValueError(err_msg)


class Digest(ABC):
    @cached_property
    def size(self) -> int:
        return len(self.compute(b""))

    @abstractmethod
    def compute(self, message: bytes) -> bytes:
        pass

    def check(self, message: bytes, fingerprint: bytes) -> bool:
        return fingerprint == self.compute(message)


class EncryptedDigest(Digest):
    def __init__(self, digest: Digest, cipher: Cipher) -> None:
        self._digest = digest
        self._cipher = cipher

    def compute(self, message: bytes) -> bytes:
        iv = os.urandom(self._cipher.iv_size) if self._cipher.iv_size else b""
        return iv + self._cipher.encrypt(self._digest.compute(message), iv)

    def check(self, message: bytes, fingerprint: bytes) -> bool:
        iv = None
        if self._cipher.iv_size:
            iv = fingerprint[: self._cipher.iv_size]
            fingerprint = fingerprint[self._cipher.iv_size :]
        try:
            fingerprint = self._cipher.decrypt(fingerprint, iv)
        except ValueError:
            return False
        return self._digest.check(message, fingerprint)


class XOR(Digest):
    size = 8

    def compute(self, message: bytes) -> bytes:
        message = zero_pad(message, self.size)
        digest = bytes(self.size)
        for i in range(len(message) // self.size):
            digest = xor(digest, message[i * self.size : (i + 1) * self.size])
        return digest


class SHA256(Digest):
    size = 32

    def compute(self, message: bytes) -> bytes:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(message)
        return digest.finalize()