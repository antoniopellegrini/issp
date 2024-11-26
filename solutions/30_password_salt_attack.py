# Crack as many passwords as possible from a password database containing hashed and salted
# passwords using a dictionary attack.
#
# Hint: you can either precompute all hashed passwords for all salt values, or just
#       compute hashes on-the-fly as needed. Which approach is more efficient, and why?

from itertools import islice

from issp import common_passwords, generate_password_database, log, scrypt_fast


def main() -> None:
    hash_func = scrypt_fast
    db = generate_password_database(100, hash_function=hash_func, salt_length=8)

    log.info("First 10 database entries:")
    for user, data in islice(db.items(), 10):
        log.info("User %d: %s", user, data)

    common = common_passwords()
    cracked = {}  # User ID -> plaintext password

    for i, data in log.percent(db.items(), "Cracking passwords"):
        for password in common:
            if hash_func(password, salt=data["salt"]) == data["password"]:
                cracked[i] = password
                log.info("Password for user %d: %s", i, password)
                continue

    log.info("Cracked passwords: %d of %d", len(cracked), len(db))
    log.info("First 10 cracked passwords:")
    for i, password in islice(cracked.items(), 10):
        log.info("%d: %s", i, password)


if __name__ == "__main__":
    main()
