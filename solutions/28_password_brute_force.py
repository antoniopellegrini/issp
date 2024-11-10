# Crack the provided password using a brute-force attack.

import itertools
import string
from collections.abc import Iterator

from issp import log, random_common_password, sha256


def brute_force(charset: str) -> Iterator[str]:
    for length in itertools.count(start=1):
        for pwd in itertools.product(charset, repeat=length):
            yield "".join(pwd)


def main() -> None:
    charset = string.ascii_lowercase
    password = random_common_password(length=5, charset=charset)
    log.info("Password to crack: %s", password)

    # Note: we are deliberately using a fast hash function to make brute-forcing feasible
    #       in a reasonable amount of time. Try changing the hash function to scrypt to see
    #       how much slower the brute-forcing process becomes.
    hash_func = sha256
    password = hash_func(password.encode())

    for current_password in log.progress(brute_force(charset), desc="Cracking password"):
        if hash_func(current_password.encode()) == password:
            log.info("Password found: %s", current_password)
            break


if __name__ == "__main__":
    main()
