"""Intentional performance problems — benchmark fixture for the optimizer."""
import re
import sqlite3


def load_orders(conn: sqlite3.Connection, user_ids):
    orders = []
    for uid in user_ids:  # N+1: one query per user
        cur = conn.execute("SELECT * FROM orders WHERE user_id = ?", (uid,))
        orders.extend(cur.fetchall())
    return orders


def build_report(rows):
    out = ""
    for row in rows:  # quadratic string building
        out += str(row) + "\n"
    return out


def find_duplicates(items):
    dupes = []
    for a in items:
        for b in items:  # O(n^2)
            if a is not b and a == b:
                dupes.append(a)
    return dupes


def count_emails(lines):
    n = 0
    for line in lines:
        if re.search(r"\w+@\w+\.com", line):
            n += 1
    return n
