# Secure the communication between Alice and Bob by adding a stack of security layers
# made up of an AES encryption layer and an HMAC digest layer, and inspect the output of
# each layer after sending a message from Alice to Bob.
#
# Hint: The output of each layer can be retrieved by calling the receive() method on the layer.


from issp import Actor, Channel


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()

    alice.send(channel, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    bob.receive(channel)


if __name__ == "__main__":
    main()
