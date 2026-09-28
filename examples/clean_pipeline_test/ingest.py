"""Safe ingestion step for a tiny ETL-style pipeline."""

import json
import tempfile
import urllib.parse
from pathlib import Path


def load_payload(raw_bytes: bytes) -> dict:
    # Safe: structured deserialization instead of pickle.
    return json.loads(raw_bytes.decode("utf-8"))


def fetch_remote_file(filename: str, dest_dir: Path) -> Path:
    # Safe: no shell/subprocess involved; path confined to dest_dir.
    safe_name = Path(filename).name
    dest_url = urllib.parse.urljoin("https://example.com/data/", safe_name)
    dest_path = dest_dir / safe_name
    dest_path.write_text(f"fetched from {dest_url}")
    return dest_path


def cleanup(path: Path) -> None:
    # Safe: direct filesystem call, no shell interpolation.
    path.unlink(missing_ok=True)


def make_scratch_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="pipeline_"))
