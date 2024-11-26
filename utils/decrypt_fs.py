# Note: this script must be copied to the sandbox environment before being
# executed, or it won't work. Make sure to set the RSA_PRIVATE_KEY variable.

from issp import AES, RSA, System, log

RSA_PRIVATE_KEY = b""


def main() -> None:
    system = System()
    rsa = RSA(private_key=RSA_PRIVATE_KEY)

    # Decrypt key.
    key_file = system.path("/key")
    try:
        key = rsa.decrypt(key_file.read_bytes())
    except FileNotFoundError:
        log.error("Key file not found")
        return

    # Decrypt files.
    log.info("Decrypting files...")
    decryptor = AES(key)
    for path in system.path("/").walk():
        if path.is_file() and path.name.endswith(".encrypted"):
            with path.open("rb") as f:
                data = f.read()
            with system.path(str(path)[:-10]).open("wb") as f:
                f.write(decryptor.decrypt(data))
            path.remove()

    # Cleanup.
    key_file.remove()
    log.info("Done")


if __name__ == "__main__":
    main()
