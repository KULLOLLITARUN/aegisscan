"""Benchmark corpus: safe cryptography and randomness. Nothing here should be flagged."""
import hashlib
import hmac
import secrets


def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)


def fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def cache_key(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def reset_token() -> str:
    return secrets.token_urlsafe(32)


def verify(expected: bytes, actual: bytes) -> bool:
    return hmac.compare_digest(expected, actual)
