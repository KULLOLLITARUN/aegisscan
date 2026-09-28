"""
Clean Python project — well-written code for false-positive baseline (plan §7).

Uses parameterized queries and env-var secrets.
Expected finding count: 0.
"""
import os
import sqlite3


def get_db():
    return sqlite3.connect(os.environ["DATABASE_URL"])


def get_user(user_id: int):
    """Parameterized query — no SQL injection risk."""
    conn = get_db()
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def search_products(keyword: str):
    """Parameterized LIKE query."""
    conn = get_db()
    return conn.execute(
        "SELECT * FROM products WHERE name LIKE ?", (f"%{keyword}%",)
    ).fetchall()


def update_user_email(user_id: int, new_email: str):
    """Parameterized UPDATE — no SQL injection risk."""
    conn = get_db()
    conn.execute(
        "UPDATE users SET email = ? WHERE id = ?",
        (new_email, user_id),
    )
    conn.commit()


def format_greeting(name: str) -> str:
    """Pure function — no I/O, no risk."""
    return f"Hello, {name}!"
