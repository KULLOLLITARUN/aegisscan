"""Tiny vulnerable pipeline entrypoint."""

from config import JWT_SECRET
from ingest import cleanup, fetch_remote_file, load_payload
from transform import build_update_query, enrich_record, weak_fingerprint


def run(raw_payload: bytes, filename: str, user_id: str, email: str) -> dict:
    downloaded = fetch_remote_file(filename)
    record = load_payload(raw_payload)
    enriched = enrich_record(record, "record.get('amount', 0) * 1.2")
    enriched["fingerprint"] = weak_fingerprint(JWT_SECRET)
    enriched["query"] = build_update_query(user_id, email)
    cleanup(downloaded)
    return enriched

