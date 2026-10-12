# INTENTIONALLY VULNERABLE - CWE-330 / OWASP A02:2021.
import random
import string

def generate_reset_token():
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(16))

def generate_session_id():
    return str(random.randint(100000, 999999))
