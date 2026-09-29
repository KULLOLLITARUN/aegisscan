"""Benchmark corpus: weak cryptography and randomness (CWE-327 / CWE-338). Intentionally vulnerable."""
import hashlib
import random


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def fingerprint(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def reset_token() -> str:
    return str(random.randint(0, 10**8))
