# Crack as many passwords as possible from a password database containing hashed passwords
# using a dictionary attack.
#
# Hint: The dictionary should countain hashed passwords as keys and plaintext passwords as values.

from itertools import islice

from issp import common_passwords, generate_password_database, log, scrypt_fast


def main() -> None:
    hash_func = scrypt_fast
    db = generate_password_database(10000, hash_function=hash_func, salt_length=0)

    log.info("First 10 database entries:")
    for user, data in islice(db.items(), 10):
        log.info("User %d: %s", user, data)

    common = common_passwords()
    cracked = {}  # User ID -> plaintext password

    pwd_dict = {
        hash_func(password.encode()): password
        for password in log.percent(common, "Populating password dictionary")
    }

    for i, data in log.percent(db.items(), "Cracking passwords"):
        if password := pwd_dict.get(data["password"]):
            cracked[i] = password

    log.info("Cracked passwords: %d of %d", len(cracked), len(db))
    log.info("First 10 cracked passwords:")
    for i, password in islice(cracked.items(), 10):
        log.info("%d: %s", i, password)


if __name__ == "__main__":
    main()
