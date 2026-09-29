"""Benchmark corpus: safe database access. Nothing here should be flagged."""
import sqlite3

_ALLOWED_SORT = {"name": "name", "created": "created_at"}


def find_user(conn: sqlite3.Connection, name):
    return conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()


def find_many(conn: sqlite3.Connection, ids):
    marks = ",".join("?" for _ in ids)
    return conn.execute(f"SELECT * FROM users WHERE id IN ({marks})", list(ids)).fetchall()


def list_users(conn: sqlite3.Connection, sort_key):
    column = _ALLOWED_SORT.get(sort_key, "name")
    return conn.execute("SELECT * FROM users ORDER BY " + column).fetchall()


def rename(conn: sqlite3.Connection, uid, new_name):
    conn.execute("UPDATE users SET name = ? WHERE id = ?", (new_name, uid))
    conn.commit()
