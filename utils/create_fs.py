# For safety reasons, malware exercises will be run in a sandbox environment. The sandbox is a
# directory that contains a number of files and directories. All interactions with the sandbox
# must be done through the System class of the issp library and its Path objects.
#
# The sandbox environment is created by running the present script, and it will be created
# in the "fs" directory in the project root. Note that the sandbox will be wiped clean before
# being populated with the initial files and directories.
#
# Scripts implementing malware exercises must be copied to the sandbox environment before being
# executed, or they won't work.

from issp import System


def main() -> None:
    system = System(validate_sandbox=False)
    system.restore_fs(wipe=True)


if __name__ == "__main__":
    main()
