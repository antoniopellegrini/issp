# Secure the communication between Alice and Bob by adding a stack of security layers
# made up of digital envelope encryption digitally signed through RSA.
# Inspect the output of each layer after sending a message from Alice to Bob.
#
# Hint: You can use the DigitalEnvelope and RSASigner classes from the issp library.


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
