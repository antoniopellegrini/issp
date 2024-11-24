from __future__ import annotations

import os
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives import ciphers, hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding, rsa
from cryptography.hazmat.primitives.ciphers import algorithms, modes

from ._communication import Layer
from ._util import xor


class EncryptionLayer(Layer):
    def __init__(self, layer: Layer | None = None, cipher: Cipher | None = None) -> None:
        super().__init__(layer)
        self._cipher = cipher

    def send(self, message: bytes) -> None:
        if self._cipher.iv_size:
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
        if self._cipher.iv_size:
            kwargs["iv"] = message[: self._cipher.iv_size]
            message = message[self._cipher.iv_size :]
        return self._cipher.decrypt(message, **kwargs)


class Cipher(ABC):
    @property
    def iv_size(self) -> int:
        return 0

    @property
    def key_size(self) -> int:
        return 0

    @abstractmethod
    def encrypt(self, message: bytes, *, iv: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, message: bytes, *, iv: bytes) -> bytes:
        pass


class SymmetricCipher(Cipher, ABC):
    @property
    def default_key_size(self) -> int:
        return 0

    @property
    def key_size(self) -> int:
        return len(self.key)

    def __init__(self, key: bytes | None = None) -> None:
        super().__init__()
        self.key = key or os.urandom(self.default_key_size)


class BlockCipher(SymmetricCipher, ABC):
    @property
    def block_size(self) -> int:
        return self.iv_size


class AsymmetricCipher(Cipher, ABC):
    @property
    @abstractmethod
    def public_key(self) -> bytes:
        pass

    @property
    @abstractmethod
    def private_key(self) -> bytes:
        pass


class OTP(SymmetricCipher):
    default_key_size = 256

    def _xor(self, data: bytes) -> bytes:
        if len(data) > len(self.key):
            err_msg = f"Data ({len(data)} B) is too long for the key ({len(self.key)} B)"
            raise ValueError(err_msg)
        return xor(data, self.key)

    def encrypt(self, data: bytes) -> bytes:
        return self._xor(data)

    def decrypt(self, data: bytes) -> bytes:
        return self._xor(data)


class AES(BlockCipher):
    iv_size = 16
    default_key_size = 32
    _pad = padding.PKCS7(iv_size * 8)

    def __init__(self, key: bytes | None = None) -> None:
        super().__init__(key)
        self.apply_padding = True

    def encrypt(self, message: bytes, iv: bytes | None = None) -> bytes:
        mode = modes.CBC(iv) if iv else modes.ECB()  # noqa: S305
        encryptor = ciphers.Cipher(algorithms.AES(self.key), mode).encryptor()
        if self.apply_padding:
            padder = self._pad.padder()
            message = padder.update(message) + padder.finalize()
        return encryptor.update(message) + encryptor.finalize()

    def decrypt(self, message: bytes, iv: bytes | None = None) -> bytes:
        mode = modes.CBC(iv) if iv else modes.ECB()  # noqa: S305
        decryptor = ciphers.Cipher(algorithms.AES(self.key), mode).decryptor()
        message = decryptor.update(message) + decryptor.finalize()
        if self.apply_padding:
            unpadder = self._pad.unpadder()
            message = unpadder.update(message) + unpadder.finalize()
        return message


class ChaCha(SymmetricCipher):
    iv_size = 16
    default_key_size = 32

    def encrypt(self, message: bytes, iv: bytes) -> bytes:
        cipher = ciphers.Cipher(algorithms.ChaCha20(self.key, iv), mode=None)
        return cipher.encryptor().update(message)

    def decrypt(self, message: bytes, iv: bytes) -> bytes:
        cipher = ciphers.Cipher(algorithms.ChaCha20(self.key, iv), mode=None)
        return cipher.decryptor().update(message)


class RSA(AsymmetricCipher):
    _hash = hashes.SHA256()
    _padding = asymmetric_padding.OAEP(
        mgf=asymmetric_padding.MGF1(algorithm=_hash),
        algorithm=_hash,
        label=None,
    )

    @property
    def public_key(self) -> bytes | None:
        return self._public_key_bytes

    @public_key.setter
    def public_key(self, key: bytes) -> None:
        self._public_key_bytes = key
        self._public_key = serialization.load_pem_public_key(key) if key else None

    @property
    def private_key(self) -> bytes | None:
        return self._private_key_bytes

    @private_key.setter
    def private_key(self, key: bytes) -> None:
        self._private_key_bytes = key
        self._private_key = serialization.load_pem_private_key(key, password=None) if key else None

    @property
    def key_size(self) -> int:
        return self._public_key.key_size // 8

    def __init__(
        self,
        public_key: bytes | int | None = None,
        private_key: bytes | None = None,
    ) -> None:
        if public_key is None and private_key is None:
            public_key = 2048

        if isinstance(public_key, int):
            self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=public_key)
            self._private_key_bytes = self._private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
            self._public_key = self._private_key.public_key()
            self._public_key_bytes = self._public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            self.public_key = public_key
            self.private_key = private_key

    def encrypt(self, message: bytes) -> bytes:
        if not self._public_key:
            err_msg = "Cannot encrypt without a public key"
            raise ValueError(err_msg)
        return self._public_key.encrypt(message, self._padding)

    def decrypt(self, message: bytes) -> bytes:
        if not self._private_key:
            err_msg = "Cannot decrypt without a private key"
            raise ValueError(err_msg)
        return self._private_key.decrypt(message, self._padding)


class DigitalEnvelope(Cipher):
    @property
    def iv_size(self) -> int:
        return self.message_cipher.iv_size

    def __init__(
        self,
        message_cipher: SymmetricCipher,
        key_cipher: AsymmetricCipher,
    ) -> None:
        self.message_cipher = message_cipher
        self.key_cipher = key_cipher

    def encrypt(self, message: bytes, iv: bytes) -> bytes:
        key = os.urandom(self.message_cipher.default_key_size)
        self.message_cipher.key = key
        enc_key = self.key_cipher.encrypt(key)
        enc_message = self.message_cipher.encrypt(message, iv)
        return enc_message + enc_key

    def decrypt(self, message: bytes, iv: bytes) -> bytes:
        self.message_cipher.key = self.key_cipher.decrypt(message[-self.key_cipher.key_size :])
        return self.message_cipher.decrypt(message[: -self.key_cipher.key_size], iv)
