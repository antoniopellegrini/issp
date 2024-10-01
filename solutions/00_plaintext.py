# Introduce a third actor, Mallory, who intercepts and alters the message from Alice to Bob.

from issp import Actor, Channel


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    mallory = Actor("Mallory", quiet=True)
    channel = Channel()

    alice.send(channel, b"Hello, Bob! - Alice")
    mallory.receive(channel)
    mallory.send(channel, b"#!%* you, Bob! - Alice")
    bob.receive(channel)


if __name__ == "__main__":
    main()
