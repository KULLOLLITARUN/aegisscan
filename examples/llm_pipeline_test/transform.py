"""Unsafe transform step for scanner testing."""

import hashlib


def enrich_record(record: dict, expression: str) -> dict:
    # Vulnerability: arbitrary code execution.
    record["score"] = eval(expression)
    return record


def weak_fingerprint(value: str) -> str:
    # Vulnerability: weak hash for security-sensitive fingerprinting.
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def build_update_query(user_id: str, email: str) -> str:
    # Vulnerability: SQL injection via string concatenation.
    return "UPDATE users SET email = '" + email + "' WHERE id = " + user_id

