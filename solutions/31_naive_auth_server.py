# 1) Implement a naive authentication protocol where the user authenticates by sending
#    a username and password to the server. The server should store the password hashed
#    and salted using a slow hash function.
#
# 2) Help Mallory attack the protocol by replaying Alice's transaction request.

import os

from issp import (
    AES,
    Actor,
    AuthenticationLayer,
    BankServer,
    Channel,
    EncryptionLayer,
    RSASigner,
    log,
    scrypt,
)


class Server(BankServer):
    def register(self, msg: dict[str, str | bytes]) -> bool:
        user = msg["user"]

        if user in self.db:
            return False

        self.db[user] = {
            "salt": (salt := os.urandom(16)),
            "password": scrypt(msg["password"], salt=salt),
            "balance": msg["balance"],
        }
        return True

    def authenticate(self, msg: dict[str, str | bytes]) -> bool:
        if (record := self.db.get(msg["user"])) is None:
            return False
        return scrypt(msg["password"], salt=record["salt"]) == record["password"]


def main() -> None:
    alice = Actor("Alice")
    mallory = Actor("Mallory")
    server = Server("Server")
    channel = Channel()
    secure_channel = EncryptionLayer(cipher=AES()) | AuthenticationLayer(auth=RSASigner()) | channel

    # Registration.
    message = {
        "action": "register",
        "user": mallory.name,
        "password": "s3cr3t",
        "balance": 1000.0,
    }
    mallory.send(channel, message)
    server.handle_request(channel)

    alice_password = "p4ssw0rd"
    message = {
        "action": "register",
        "user": alice.name,
        "password": alice_password,
        "balance": 100000.0,
    }
    alice.send(secure_channel, message)
    server.handle_request(secure_channel)

    # Authenticated transaction.
    message = {
        "action": "perform_transaction",
        "user": alice.name,
        "password": alice_password,
        "recipient": "Mallory",
        "amount": 1000.0,
    }
    alice.send(secure_channel, message)
    captured_request = mallory.receive(channel)
    server.handle_request(secure_channel)

    # Replay an authenticated transaction request.
    log.info("Replaying authenticated transaction request...")
    mallory.send(channel, captured_request)
    server.handle_request(secure_channel)


if __name__ == "__main__":
    main()
