# INTENTIONALLY VULNERABLE - CWE-798 / OWASP A07:2021.
DATABASE_PASSWORD = "SuperSecret123!"
API_KEY = "EXAMPLE_NOT_A_REAL_SECRET"
JWT_SECRET = "my_jwt_secret_key_2024"

def connect():
    return f"postgresql://admin:{DATABASE_PASSWORD}@localhost/db"
