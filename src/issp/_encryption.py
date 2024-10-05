from __future__ import annotations

import os
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives import ciphers, hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding, rsa
from cryptography.hazmat.primitives.ciphers import algorithms, modes

from ._communication import Layer
from ._util import xor


class EncryptionLayer(Layer):
    def __init__(self, layer: Layer | None = None, cipher: Cipher | None = None) -> None:
        super().__init__(layer)
        self._cipher = cipher

    def send(self, message: bytes) -> None:
        if isinstance(self._cipher, SymmetricCipher) and self._cipher.iv_size:
            iv = os.urandom(self._cipher.iv_size)
            kwargs = {"iv": iv}
        else:
            iv = None
            kwargs = {}
        message = self._cipher.encrypt(message, **kwargs)
        if iv:
            message = iv + message
        self.lower_layer.send(message)

    def receive(self) -> bytes | None:
        if (message := self.lower_layer.receive()) is None:
            return None
        kwargs = {}
        if isinstance(self._cipher, SymmetricCipher) and self._cipher.iv_size:
            kwargs["iv"] = message[: self._cipher.iv_size]
            message = message[self._cipher.iv_size :]
        return self._cipher.decrypt(message, **kwargs)


class Cipher(ABC):
    @abstractmethod
    def encrypt(self, message: bytes, *, iv: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, message: bytes, *, iv: bytes) -> bytes:
        pass


class SymmetricCipher(Cipher, ABC):
    @property
    def iv_size(self) -> int:
        return 0

    @property
    def default_key_size(self) -> int:
        return 0

    def __init__(self, key: bytes | None = None) -> None:
        super().__init__()
        self.key = key or os.urandom(self.default_key_size)


class AsymmetricCipher(Cipher, ABC):
    pass


class OTP(SymmetricCipher):
    default_key_size = 256

    def encrypt(self, data: bytes) -> bytes:
        return xor(data, self.key)

    def decrypt(self, data: bytes) -> bytes:
        return xor(data, self.key)


class AES(SymmetricCipher):
    iv_size = 16
    default_key_size = 32
    _pad = padding.PKCS7(iv_size * 8)

    def encrypt(self, message: bytes, iv: bytes) -> bytes:
        encryptor = ciphers.Cipher(algorithms.AES(self.key), modes.CBC(iv)).encryptor()
        padder = self._pad.padder()
        message = padder.update(message) + padder.finalize()
        return encryptor.update(message) + encryptor.finalize()

    def decrypt(self, message: bytes, iv: bytes) -> bytes:
        decryptor = ciphers.Cipher(algorithms.AES(self.key), modes.CBC(iv)).decryptor()
        unpadder = self._pad.unpadder()
        message = decryptor.update(message) + decryptor.finalize()
        return unpadder.update(message) + unpadder.finalize()


class ChaCha(SymmetricCipher):
    iv_size = 16
    default_key_size = 32

    def encrypt(self, message: bytes, iv: bytes) -> bytes:
        cipher = ciphers.Cipher(algorithms.ChaCha20(self.key, iv), mode=None)
        return cipher.encryptor().update(message)

    def decrypt(self, message: bytes, iv: bytes) -> bytes:
        cipher = ciphers.Cipher(algorithms.ChaCha20(self.key, iv), mode=None)
        return cipher.decryptor().update(message)


class RSACipher(AsymmetricCipher):
    _hash = hashes.SHA256()
    _padding = asymmetric_padding.OAEP(
        mgf=asymmetric_padding.MGF1(algorithm=_hash),
        algorithm=_hash,
        label=None,
    )

    def __init__(self, key: rsa.RSAPublicKey | rsa.RSAPrivateKey | None = None) -> None:
        if key is None:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        if isinstance(key, rsa.RSAPrivateKey):
            self.private_key = key
            self.public_key = key.public_key()
        else:
            self.private_key = None
            self.public_key = key

    def encrypt(self, message: bytes) -> bytes:
        return self.public_key.encrypt(message, self._padding)

    def decrypt(self, message: bytes) -> bytes:
        if not self.private_key:
            err_msg = "Cannot decrypt without a private key"
            raise ValueError(err_msg)
        return self.private_key.decrypt(message, self._padding)
