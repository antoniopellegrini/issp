# Implement a scareware virus that infects all Python files on the system. The virus should
# avoid infecting the same file multiple times.
#
# Note: follow the instructions in "utils/create_fs.py"

from issp import Malware, Propagation, Scareware, System


class PyVirus(Propagation):
    def propagate(self, system: System) -> None:
        # Implement.
        pass


def main() -> None:
    malware = Malware(payload=Scareware(), propagation=PyVirus())
    malware.execute()


if __name__ == "__main__":
    main()
