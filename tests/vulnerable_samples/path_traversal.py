# INTENTIONALLY VULNERABLE - CWE-22 / OWASP A01:2021.
def read_user_file(filename):
    path = "/var/app/uploads/" + filename
    with open(path, "r") as f:
        return f.read()
