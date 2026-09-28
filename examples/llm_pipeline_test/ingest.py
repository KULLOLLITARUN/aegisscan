"""Unsafe ingestion step for a tiny ETL-style pipeline."""

import os
import pickle
import subprocess


def load_payload(raw_bytes: bytes) -> dict:
    # Vulnerability: untrusted deserialization.
    return pickle.loads(raw_bytes)


def fetch_remote_file(filename: str) -> str:
    # Vulnerability: command injection through shell=True.
    cmd = f"curl https://example.com/data/{filename} -o /tmp/{filename}"
    subprocess.run(cmd, shell=True, check=False)
    return f"/tmp/{filename}"


def cleanup(path: str) -> None:
    # Vulnerability: shell command built from user-controlled input.
    os.system(f"rm -f {path}")

