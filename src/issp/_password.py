import os
import random
import string
import time
from abc import abstractmethod
from collections.abc import Callable
from functools import cache
from pathlib import Path

from . import _log as log
from ._functions import hmac_sha1, scrypt
from ._random import random_choice, random_int, random_string

RES_DIR = Path(__file__).parent / "res"


def _hotp(key: bytes, counter: int, digits: int = 6) -> int:
    mac = hmac_sha1(counter.to_bytes(8), key)
    return (int.from_bytes(mac) & 0x7FFFFFFF) % 10**digits


class OTPGenerator:
    @abstractmethod
    def get_otp(self) -> int:
        pass

    @abstractmethod
    def synchronize(self, value: int) -> None:
        pass


class HOTP(OTPGenerator):
    def __init__(self, key: bytes, digits: int = 6, counter: int = 0) -> None:
        self._key = key
        self._digits = max(1, min(10, digits))
        self._counter = max(0, counter)

    def get_otp(self) -> int:
        self._counter += 1
        return _hotp(self._key, self._counter, self._digits)

    def synchronize(self, value: int) -> None:
        self._counter = value


class TOTP(OTPGenerator):
    def __init__(self, key: bytes, digits: int = 6, period: int = 30, epoch: int = 0) -> None:
        self._key = key
        self._digits = max(1, min(10, digits))
        self._period = max(1, period)
        self._epoch = epoch

    def get_otp(self) -> int:
        counter = int((time.time() - self._epoch) / self._period)
        return _hotp(self._key, counter, self._digits)

    def synchronize(self, value: int) -> None:
        self._epoch = value


@cache
def common_passwords() -> list[str]:
    with (RES_DIR / "10-million-password-list-top-10000.txt").open() as f:
        return f.read().splitlines()


def random_common_password(length: int = 5, charset: str = string.ascii_lowercase) -> str:
    pwds = [p for p in common_passwords() if len(p) == length and all(c in charset for c in p)]
    if not pwds:
        err_msg = "No suitable password found"
        raise ValueError(err_msg)
    return random_choice(pwds)


def generate_password_database(
    length: int,
    random_ratio: float = 0.5,
    random_min_length: int = 8,
    random_max_length: int = 16,
    hash_function: Callable[[bytes, bytes | None], bytes] | None = scrypt,
    salt_length: int = 16,
) -> dict[int, dict[str, bytes]]:
    common = common_passwords()
    repeat_common = length // len(common) + 1
    random_count = int(length * random_ratio)
    common_count = length - random_count

    charset = string.ascii_letters + string.digits
    passwords = [
        random_string(random_int(random_min_length, random_max_length), charset=charset)
        for _ in range(random_count)
    ]
    passwords.extend(random.sample(common, counts=[repeat_common] * len(common), k=common_count))
    random.shuffle(passwords)

    pass_dict: dict[int, dict[str, bytes]] = {
        i: {"password": password.encode()} for i, password in enumerate(passwords)
    }

    if hash_function is not None:
        for data in log.percent(pass_dict.values(), "Generating password database"):
            if salt_length > 0:
                salt = os.urandom(16)
                data["salt"] = salt
            else:
                salt = None
            data["password"] = hash_function(data["password"], salt=salt)

    return pass_dict
