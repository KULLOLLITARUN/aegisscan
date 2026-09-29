"""Look-alikes that must NOT be flagged (precision fixture for the optimizer)."""
import re
import sqlite3

PATTERN = re.compile(r"\w+@\w+\.com")


def batch_query(conn: sqlite3.Connection, ids):
    placeholders = ",".join("?" for _ in ids)
    return conn.execute(f"SELECT * FROM t WHERE id IN ({placeholders})", ids).fetchall()


def join_parts(rows):
    parts = []
    for row in rows:
        parts.append(str(row))
    return "\n".join(parts)


def cross_product(xs, ys):
    return [(x, y) for x in xs for y in ys]  # two different collections


def nested_different(xs, ys):
    out = 0
    for x in xs:
        for y in ys:
            out += x * y
    return out


def count_numbers(values):
    total = 0
    for v in values:
        total += v  # numeric +=, not a string
    return total


def matches(lines):
    return [line for line in lines if PATTERN.search(line)]


def define_in_loop(items):
    for item in items:
        def later(c):  # body only runs when called, not per iteration
            return c.execute("SELECT 1")
        item.callback = later
