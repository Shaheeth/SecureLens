# INTENTIONALLY VULNERABLE - CWE-327 / OWASP A02:2021.
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def hash_password_sha1(password):
    return hashlib.sha1(password.encode()).hexdigest()
