"""
Vulnerable Python auth module — intentional security issues for benchmark testing.

DO NOT deploy this code.

Expected Bandit findings:
  B324 - hashlib (MD5 usage for password hashing)
  B105 - hardcoded_password_string (SECRET_KEY, ADMIN_PASSWORD)
  B101 - assert_used (assert for auth check in production code)
"""
import hashlib

# B105: hardcoded_password_string
SECRET_KEY = "my-super-secret-jwt-key-do-not-share"
ADMIN_PASSWORD = "letmein"


def hash_password(password: str) -> str:
    """B324: MD5 is cryptographically broken — never use for passwords."""
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password: str, stored_hash: str) -> bool:
    """B324: still using MD5."""
    return hashlib.md5(password.encode()).hexdigest() == stored_hash


def require_admin(user):
    """B101: assert used for security check — disabled with -O flag."""
    assert user.get("role") == "admin", "Admin required"


def generate_token(user_id: int) -> str:
    """Insecure token — predictable, no expiry."""
    raw = f"{user_id}:{SECRET_KEY}"
    return hashlib.md5(raw.encode()).hexdigest()
