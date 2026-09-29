"""More intentional performance problems — labelled benchmark fixture (see EXPECTED in tests)."""
import requests


def fetch_profiles(session, ids):
    profiles = []
    for pid in ids:  # network call per item
        profiles.append(session.get(f"/profiles/{pid}"))
    return profiles


def rows_to_csv(rows):
    text = ""
    i = 0
    while i < len(rows):  # string built in a while loop
        text += ",".join(rows[i]) + "\n"
        i += 1
    return text


def enrich(conn, users):
    return [conn.execute("SELECT 1 WHERE ?", (u,)).fetchone() for u in users]  # query in comprehension


def pairwise(points):
    total = 0
    for p in points:
        for q in points:  # quadratic
            total += abs(p - q)
    return total


def head():
    return requests.get("/health")  # NOT in a loop: must not be flagged
