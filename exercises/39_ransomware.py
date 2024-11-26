# Implement a ransomware that encrypts all files on the system and propagates itself
# to the root directory and to all storage devices. Directives:
#
# - Encryption should be done using AES with a randomly generated key that is encrypted
#   using the attacker's public RSA key.
# - The attacker's public and private RSA keys should be logged to the console to
#   allow file decryption using the "utils/decrypt_fs.py" script.
#   Note that in a real scenario the attacker would, of course, keep the private key secret
#   and only ship the public key with the malware.
# - The encrypted AES key should be stored in a "key" file in the root directory of the sandbox.
# - Encrypted files should have the ".encrypted" extension.
#
# Note: follow the instructions in "utils/create_fs.py"


from issp import Malware, Payload, StorageWorm, System


class Ransomware(Payload):
    def execute(self, system: System) -> None:
        # Implement.
        pass


def main() -> None:
    malware = Malware(payload=Ransomware(), propagation=StorageWorm())
    malware.execute()


if __name__ == "__main__":
    main()
