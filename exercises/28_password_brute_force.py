# Crack the provided password using a brute-force attack.
#
# Hint: You can use itertools.product to generate all possible passwords of a given length,
#       and itertools.count to generate all possible lengths.

import string

from issp import log, random_common_password, sha256


def main() -> None:
    charset = string.ascii_lowercase
    password = random_common_password(length=5, charset=charset)
    log.info("Password to crack: %s", password)

    # Note: we are deliberately using a fast hash function to make brute-forcing feasible
    #       in a reasonable amount of time. Try changing the hash function to scrypt to see
    #       how much slower the brute-forcing process becomes.
    hash_func = sha256
    password = hash_func(password.encode())

    # Crack the password.


if __name__ == "__main__":
    main()
