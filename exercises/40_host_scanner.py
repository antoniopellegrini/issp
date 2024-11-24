# Implement a signature-based malware scanner. Directives:
#
# - The scanner must be able to detect all the malware variants created in the previous exercises.
# - Detected malware should be quarantined by moving it to the "/quarantine" directory.
# - To avoid overwriting infected files with identical names, the quarantine directory
#   should mirror the structure of the root directory.
#
# Hint: use the re module to search for malware signatures using regular expressions.
# Hint: it is a good idea to avoid scanning the quarantine directory and the scanner itself.
#
# Note: follow the instructions in "utils/create_fs.py"


from issp import Path, System, log


def main() -> None:
    system = System()
    quarantine_dir = system.path("/quarantine")

    # Malware variant -> signature.
    signatures = {}

    # Path -> malware variant.
    detections: dict[Path, str] = {}

    # Detect infected files.

    if not detections:
        log.info("No malware detected.")
        return

    log.info("Malware detected:")

    # Log and quarantine infected files.


if __name__ == "__main__":
    main()
