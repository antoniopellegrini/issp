# Introduce a third actor, Mallory, who intercepts and alters the message from Alice to Bob.

from issp import Actor, Channel


def main() -> None:
    alice = Actor("Alice")
    bob = Actor("Bob")
    channel = Channel()

    alice.send(channel, b"Hello, Bob! - Alice")
    bob.receive(channel)


if __name__ == "__main__":
    main()
