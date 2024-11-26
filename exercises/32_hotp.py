# 1) Implement a two-factor authentication protocol where the user authenticates by sending
#    a username, password, and HMAC-based One-Time Password (HOTP) to the server.
#    The HOTP should be 6 digits long.
#
# 2) Help Mallory attack the protocol by replaying Alice's transaction request.
#    Is the attack successful? Why?
#
# Hint: you can use the hmac_sha1 function from the issp module to compute the HMAC.
#       To compute the truncate() function, you can extract the least significant 31 bits
#       of the HMAC value (value & 0x7FFFFFFF).

import os
import time

from issp import (
    AES,
    Actor,
    AuthenticationLayer,
    BankServer,
    Channel,
    EncryptionLayer,
    RSASigner,
    log,
)


class HOTP:
    def __init__(self, key: bytes) -> None:
        self.key = key

    def get_otp(self) -> int:
        # Implement.
        return 0


class Server(BankServer):
    def register(self, msg: dict[str, str | bytes]) -> bool:
        # Implement.
        return False

    def authenticate(self, msg: dict[str, str | bytes]) -> bool:
        # Implement.
        return False


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
        "otp_key": os.urandom(16),
        "balance": 1000.0,
    }
    mallory.send(channel, message)
    server.handle_request(channel)

    alice_password = "p4ssw0rd"
    alice_otp = HOTP(os.urandom(16))
    message = {
        "action": "register",
        "user": alice.name,
        "password": alice_password,
        "otp_key": alice_otp.key,
        "balance": 100000.0,
    }
    alice.send(secure_channel, message)
    server.handle_request(secure_channel)

    # Authenticated transactions.
    transaction_count = 10
    for i in range(transaction_count):
        time.sleep(1)
        log.info("Transaction %d", i + 1)
        message = {
            "action": "perform_transaction",
            "user": alice.name,
            "password": alice_password,
            "otp": alice_otp.get_otp(),
            "recipient": "Mallory",
            "amount": 1000.0,
        }
        alice.send(secure_channel, message)
        server.handle_request(secure_channel)

    # Replay an authenticated transaction request.
    log.info("Replaying authenticated transaction request...")


if __name__ == "__main__":
    main()
