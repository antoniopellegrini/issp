import os
import random
import string
from collections.abc import Callable
from functools import cache
from pathlib import Path

from . import _log as log
from ._hash import scrypt
from ._random import random_int, random_string

RES_DIR = Path(__file__).parent / "res"


@cache
def common_passwords() -> list[str]:
    with (RES_DIR / "10-million-password-list-top-10000.txt").open() as f:
        return f.read().splitlines()


def random_common_password(length: int = 5, charset: str = string.ascii_lowercase) -> str:
    all_passwords = list(common_passwords())
    random.shuffle(all_passwords)
    for password in all_passwords:
        if len(password) == length and all(char in charset for char in password):
            break
    if password is None:
        err_msg = "No suitable password found"
        raise ValueError(err_msg)
    return password


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
