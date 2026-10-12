# SECURE reference version - canonicalized, allow-listed base path.
import os

BASE_DIR = os.path.realpath("/var/app/uploads")

def read_user_file(filename: str):
    candidate = os.path.realpath(os.path.join(BASE_DIR, filename))
    if not candidate.startswith(BASE_DIR + os.sep):
        raise ValueError("Invalid file path")
    with open(candidate, "r") as f:
        return f.read()
