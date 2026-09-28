"""Tiny safe pipeline entrypoint."""

from config import JWT_SECRET
from ingest import cleanup, fetch_remote_file, load_payload, make_scratch_dir
from transform import build_update_query, enrich_record, strong_fingerprint


def run(raw_payload: bytes, filename: str, user_id: str, email: str) -> dict:
    scratch_dir = make_scratch_dir()
    downloaded = fetch_remote_file(filename, scratch_dir)
    record = load_payload(raw_payload)
    enriched = enrich_record(record, multiplier=1.2)
    enriched["fingerprint"] = strong_fingerprint(JWT_SECRET)
    enriched["query"], enriched["query_params"] = build_update_query(user_id, email)
    cleanup(downloaded)
    return enriched
