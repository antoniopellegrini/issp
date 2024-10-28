from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def sha256(data: bytes, salt: bytes | None = None) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    if salt:
        digest.update(salt)
    return digest.finalize()


def scrypt(data: bytes, salt: bytes | None = None) -> bytes:
    return Scrypt(salt=b"" if salt is None else salt, length=32, n=2**14, r=8, p=1).derive(data)


def scrypt_fast(data: bytes, salt: bytes | None = None) -> bytes:
    return Scrypt(salt=b"" if salt is None else salt, length=32, n=2**8, r=8, p=1).derive(data)
