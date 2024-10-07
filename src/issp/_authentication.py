from __future__ import annotations

import os
from abc import ABC, abstractmethod
from functools import cached_property
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ._communication import Layer
from ._util import xor, zero_pad

if TYPE_CHECKING:
    from ._encryption import SymmetricCipher


class AuthenticationLayer(Layer):
    def __init__(self, layer: Layer = None, auth: Authenticator = None) -> None:
        super().__init__(layer)
        self.auth = auth

    def send(self, message: bytes) -> None:
        code = self.auth.compute_code(message)
        self.lower_layer.send(message + code)

    def receive(self) -> bytes | None:
        if (message := self.lower_layer.receive()) is None:
            return None

        fingerprint = message[-self.auth.code_size :]
        message = message[: -self.auth.code_size]

        if self.auth.verify(message, fingerprint):
            return message

        err_msg = "The message has been tampered with"
        raise ValueError(err_msg)


class Authenticator(ABC):
    @cached_property
    def code_size(self) -> int:
        return len(self.compute_code(b""))

    @abstractmethod
    def compute_code(self, message: bytes) -> bytes:
        pass

    def verify(self, message: bytes, code: bytes) -> bool:
        return code == self.compute_code(message)


class EncryptedHashMAC(Authenticator):
    def __init__(self, auth: Authenticator, cipher: SymmetricCipher) -> None:
        self.auth = auth
        self.cipher = cipher

    def compute_code(self, message: bytes) -> bytes:
        iv = os.urandom(self.cipher.iv_size) if self.cipher.iv_size else b""
        return iv + self.cipher.encrypt(self.auth.compute_code(message), iv)

    def verify(self, message: bytes, code: bytes) -> bool:
        iv = None
        if self.cipher.iv_size:
            iv = code[: self.cipher.iv_size]
            code = code[self.cipher.iv_size :]
        try:
            code = self.cipher.decrypt(code, iv)
        except ValueError:
            return False
        return self.auth.verify(message, code)


class KeyedHashMAC(Authenticator):
    @property
    def code_size(self) -> int:
        return self.auth.code_size

    def __init__(self, auth: Authenticator, key: bytes | None = None) -> None:
        self.auth = auth
        self.key = key or os.urandom(self.code_size)

    def compute_code(self, message: bytes) -> bytes:
        return self.auth.compute_code(self.key + message + self.key)


class XOR(Authenticator):
    code_size = 8

    def compute_code(self, message: bytes) -> bytes:
        message = zero_pad(message, self.code_size)
        digest = bytes(self.code_size)
        for i in range(0, len(message), self.code_size):
            digest = xor(digest, message[i : i + self.code_size])
        return digest


class SHA256(Authenticator):
    code_size = 32

    def compute_code(self, message: bytes) -> bytes:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(message)
        return digest.finalize()


class HMAC(Authenticator):
    code_size = 32

    def __init__(self, key: bytes | None = None) -> None:
        self.key = key or os.urandom(self.code_size)

    def compute_code(self, message: bytes) -> bytes:
        mac = hmac.HMAC(self.key, hashes.SHA256())
        mac.update(message)
        return mac.finalize()


class RSASigner(Authenticator):
    _hash = hashes.SHA256()
    _padding = padding.PSS(
        mgf=padding.MGF1(_hash),
        salt_length=padding.PSS.MAX_LENGTH,
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

    def compute_code(self, message: bytes) -> bytes:
        if not self.private_key:
            err_msg = "Cannot sign without a private key"
            raise ValueError(err_msg)
        return self.private_key.sign(message, self._padding, self._hash)

    def verify(self, message: bytes, fingerprint: bytes) -> bool:
        try:
            self.public_key.verify(fingerprint, message, self._padding, self._hash)
        except InvalidSignature:
            return False
        return True
