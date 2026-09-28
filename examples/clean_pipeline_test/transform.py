"""Safe transform step for scanner testing."""

import hashlib


def enrich_record(record: dict, multiplier: float) -> dict:
    # Safe: explicit numeric operation instead of eval().
    record["score"] = record.get("amount", 0) * multiplier
    return record


def strong_fingerprint(value: str) -> str:
    # Safe: SHA-256 instead of a weak hash for fingerprinting.
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def build_update_query(user_id: str, email: str) -> tuple[str, tuple]:
    # Safe: parameterized query, no string concatenation of user input.
    return "UPDATE users SET email = %s WHERE id = %s", (email, user_id)
