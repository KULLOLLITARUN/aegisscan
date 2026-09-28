"""
Clean Python auth module — well-written code for false-positive baseline (plan §7).

Uses bcrypt for hashing and reads secrets from environment variables.
Expected finding count: 0 (or very low false positives).
"""
import hashlib
import hmac
import os
import secrets


def hash_password(password: str) -> str:
    """
    Secure password hashing using PBKDF2-HMAC-SHA256.
    (bcrypt would be better; using stdlib to keep dependencies minimal here.)
    """
    salt = secrets.token_bytes(32)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations=260_000)
    return salt.hex() + ":" + key.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    salt_hex, key_hex = stored_hash.split(":", 1)
    salt = bytes.fromhex(salt_hex)
    key = bytes.fromhex(key_hex)
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations=260_000)
    return hmac.compare_digest(candidate, key)


def get_secret_key() -> str:
    """Read secret from environment — never hardcoded."""
    key = os.environ.get("SECRET_KEY")
    if not key:
        raise RuntimeError("SECRET_KEY environment variable is not set")
    return key


def generate_token(user_id: int) -> str:
    """Cryptographically secure random token."""
    return secrets.token_urlsafe(32)
