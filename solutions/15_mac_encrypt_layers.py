# Secure the communication between Alice and Bob by adding a stack of security layers
# made up of an AES encryption layer and an HMAC digest layer.
# Inspect the output of each layer after sending a message from Alice to Bob.
#
# Hint: The output of each layer can be retrieved by calling the receive() method
#       on the subsequent layer.


from issp import AES, HMAC, Actor, AuthenticationLayer, Channel, EncryptionLayer, log


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=False)
    channel = Channel()
    auth_layer = AuthenticationLayer(channel, HMAC())
    enc_layer = EncryptionLayer(auth_layer, AES())

    alice.send(enc_layer, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    # Uncomment the next line to let Mallory tamper with the message.
    # mallory.send(channel, mallory.receive(channel)[8:])

    try:
        log.info("Encryption output: %s", auth_layer.receive())
        log.info("Authentication output: %s", channel.receive())
    except ValueError:
        pass

    bob.receive(enc_layer)


if __name__ == "__main__":
    main()
