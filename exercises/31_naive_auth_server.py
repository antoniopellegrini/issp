# 1) Implement a naive authentication protocol where the user authenticates by sending
# a username and password to the server. The server should store the password hashed
# and salted using a slow hash function.
#
# 2) Help Mallory attack the protocol by replaying Alice's transaction request.


from issp import (
    AES,
    Actor,
    AuthenticationLayer,
    Channel,
    EncryptionLayer,
    RSASigner,
    log,
)


class Server(Actor):
    def __init__(self, name: str, *, quiet: bool = False) -> None:
        super().__init__(name, quiet=quiet)
        self._db = {}

    def handle_request(self, channel: Channel) -> None:
        message = self.receive(channel)
        action = message["action"]

        if action == "register":
            response = {"status": "success" if self._register(message) else "failure"}
        elif action == "perform_transaction":
            response = self._perform_transaction(message)
        else:
            response = {"status": "invalid request"}

        self.send(channel, response)

    def _register(self, message: dict) -> bool:
        # Implement. Return True if the registration was successful, False otherwise.
        return False

    def _login(self, message: dict) -> bool:
        # Implement. Return True if the login was successful, False otherwise.
        return False

    def _perform_transaction(self, message: dict) -> dict:
        if not self._login(message):
            return {"status": "invalid credentials"}

        try:
            user = message["user"]
            amount = message["amount"]
            recipient = message["recipient"]

            if self._db[user]["balance"] < amount:
                return {"status": "insufficient funds"}

            self._db[user]["balance"] -= amount
            self._db[recipient]["balance"] += amount
        except KeyError:
            return {"status": "invalid request"}

        log.info("Current balances: %s", {k: v["balance"] for k, v in self._db.items()})
        return {"recipient": recipient, "amount": amount, "status": "success"}


def main() -> None:
    alice = Actor("Alice")
    mallory = Actor("Mallory")
    server = Server("Server")
    channel = Channel()
    secure_channel = EncryptionLayer(cipher=AES()) | AuthenticationLayer(auth=RSASigner()) | channel

    message = {
        "user": mallory.name,
        "password": "p4ssw0rd",
        "action": "register",
        "balance": 1000.0,
    }
    mallory.send(channel, message)
    server.handle_request(channel)

    message = {
        "user": alice.name,
        "password": "p4ssw0rd",
        "action": "register",
        "balance": 100000.0,
    }
    alice.send(secure_channel, message)
    server.handle_request(secure_channel)

    message = {
        "user": alice.name,
        "password": "p4ssw0rd",
        "action": "perform_transaction",
        "recipient": "Mallory",
        "amount": 1000.0,
    }
    alice.send(secure_channel, message)
    server.handle_request(secure_channel)
    message = alice.receive(secure_channel)

    # Replay the authenticated transaction request


if __name__ == "__main__":
    main()
