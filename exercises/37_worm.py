# Implement a worm that deletes all files on the system and propagates itself
# to the root directory and to all storage devices.
#
# Note: follow the instructions in "utils/create_fs.py"

from issp import Malware, Payload, Propagation, System


class DeleteFiles(Payload):
    def execute(self, system: System) -> None:
        # Implement.
        pass


class StorageWorm(Propagation):
    def propagate(self, system: System) -> None:
        # Implement.
        pass


def main() -> None:
    malware = Malware(payload=DeleteFiles(), propagation=StorageWorm())
    malware.execute()


if __name__ == "__main__":
    main()
