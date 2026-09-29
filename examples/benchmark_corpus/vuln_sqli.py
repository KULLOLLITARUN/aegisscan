"""Benchmark corpus: SQL injection variants (CWE-89). Intentionally vulnerable."""
import sqlite3


def find_user_fstring(conn: sqlite3.Connection, name):
    return conn.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall()


def find_user_percent(conn: sqlite3.Connection, email):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = '%s'" % email)
    return cur.fetchone()


def find_user_format(conn: sqlite3.Connection, uid):
    query = "SELECT * FROM users WHERE id = {}".format(uid)
    return conn.execute(query).fetchone()


def delete_orders(conn: sqlite3.Connection, status):
    conn.execute("DELETE FROM orders WHERE status = '" + status + "'")
    conn.commit()
