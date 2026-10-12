# SECURE reference version - constant-time compare, debug disabled.
import hmac
import os

def login(username: str, password: str, stored_hash_check_fn):
    # stored_hash_check_fn should verify against a securely hashed password
    if stored_hash_check_fn(password):
        return {"status": "ok"}
    return {"status": "denied"}

def constant_time_check(secret: str, provided: str) -> bool:
    return hmac.compare_digest(secret, provided)

def run_app(app):
    app.run(debug=os.environ.get("DEBUG", "false").lower() == "true")
