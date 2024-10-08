# Implement the symmetric key distribution scheme that we have discussed in the lectures.
#
# Hint: You can use the pre-implemented ciphers from the issp module (e.g. AES or ChaCha).


from issp import Actor, Channel


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    kdc = Actor("KDC")
    channel = Channel()


if __name__ == "__main__":
    main()
