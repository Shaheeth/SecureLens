# SECURE reference version - CSPRNG via `secrets`.
import secrets

def generate_reset_token() -> str:
    return secrets.token_urlsafe(24)

def generate_session_id() -> str:
    return secrets.token_hex(16)
