from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def _hmac(data: bytes | str, key: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
    if isinstance(data, str):
        data = data.encode()
    mac = hmac.HMAC(key, algorithm)
    mac.update(data)
    return mac.finalize()


def _hash(data: bytes | str, algorithm: hashes.HashAlgorithm, salt: bytes | None = None) -> bytes:
    if isinstance(data, str):
        data = data.encode()
    digest = hashes.Hash(algorithm)
    digest.update(data)
    if salt:
        digest.update(salt)
    return digest.finalize()


def _scrypt(data: bytes | str, n: int = 2**14, salt: bytes | None = None) -> bytes:
    if isinstance(data, str):
        data = data.encode()
    return Scrypt(salt=b"" if salt is None else salt, length=32, n=n, r=8, p=1).derive(data)


def hmac_sha1(data: bytes | str, key: bytes) -> bytes:
    return _hmac(data, key, hashes.SHA1())  # noqa: S303


def hmac_sha256(data: bytes | str, key: bytes) -> bytes:
    return _hmac(data, key, hashes.SHA256())


def sha1(data: bytes | str, salt: bytes | None = None) -> bytes:
    return _hash(data, hashes.SHA1(), salt)  # noqa: S303


def sha256(data: bytes | str, salt: bytes | None = None) -> bytes:
    return _hash(data, hashes.SHA256(), salt)


def scrypt(data: bytes | str, salt: bytes | None = None) -> bytes:
    return _scrypt(data, salt=salt)


def scrypt_fast(data: bytes | str, salt: bytes | None = None) -> bytes:
    return _scrypt(data, salt=salt, n=2**8)
