from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import ciphers, padding
from cryptography.hazmat.primitives.ciphers import algorithms, modes

from ._util import xor

if TYPE_CHECKING:
    from ._comm import Layer


class EncryptionLayer:
    def __init__(self, layer: Layer, cipher: Cipher) -> None:
        self._layer = layer
        self._cipher = cipher

    def send(self, message: bytes) -> None:
        iv = os.urandom(self._cipher.iv_size) if self._cipher.iv_size else None
        message = self._cipher.encrypt(message, iv)
        if iv:
            message = iv + message
        self._layer.send(message)

    def receive(self) -> bytes | None:
        if message := self._layer.receive():
            iv = None
            if self._cipher.iv_size:
                iv = message[: self._cipher.iv_size]
                message = message[self._cipher.iv_size :]
            return self._cipher.decrypt(message, iv)
        return None


class Cipher(ABC):
    @abstractmethod
    def encrypt(self, message: bytes, iv: bytes | None) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, message: bytes, iv: bytes | None) -> bytes:
        pass

    @property
    def iv_size(self) -> int:
        return 0

    def __init__(self, key: bytes) -> None:
        self.key = key


class OTP(Cipher):
    def encrypt(self, data: bytes, iv: bytes | None) -> bytes:
        del iv  # Unused
        return xor(data, self.key)

    def decrypt(self, data: bytes, iv: bytes | None) -> bytes:
        del iv  # Unused
        return xor(data, self.key)


class AES(Cipher):
    iv_size = 16
    _pad = padding.PKCS7(iv_size * 8)

    def encrypt(self, message: bytes, iv: bytes | None) -> bytes:
        encryptor = ciphers.Cipher(algorithms.AES(self.key), modes.CBC(iv)).encryptor()
        padder = self._pad.padder()
        message = padder.update(message) + padder.finalize()
        return encryptor.update(message) + encryptor.finalize()

    def decrypt(self, message: bytes, iv: bytes) -> bytes:
        decryptor = ciphers.Cipher(algorithms.AES(self.key), modes.CBC(iv)).decryptor()
        unpadder = self._pad.unpadder()
        message = decryptor.update(message) + decryptor.finalize()
        return unpadder.update(message) + unpadder.finalize()


class ChaCha(Cipher):
    iv_size = 16

    def encrypt(self, message: bytes, iv: bytes | None) -> bytes:
        algorithm = algorithms.ChaCha20(self.key, iv)
        cipher = ciphers.Cipher(algorithm, mode=None)
        return cipher.encryptor().update(message)

    def decrypt(self, message: bytes, iv: bytes | None) -> bytes:
        algorithm = algorithms.ChaCha20(self.key, iv)
        cipher = ciphers.Cipher(algorithm, mode=None)
        return cipher.decryptor().update(message)
