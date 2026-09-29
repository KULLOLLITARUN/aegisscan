"""Benchmark corpus: safe configuration, network and file handling. Nothing here should be flagged."""
import logging
import os
import tempfile

import requests
import yaml

log = logging.getLogger(__name__)


def db_url() -> str:
    return os.environ["DATABASE_URL"]


def load_config(text: str):
    return yaml.safe_load(text)


def fetch(url: str):
    return requests.get(url, timeout=10)


def make_tmp() -> str:
    fd, path = tempfile.mkstemp()
    os.close(fd)
    return path


def restrict(path: str) -> None:
    os.chmod(path, 0o600)


def check_admin(user) -> None:
    if not user.get("admin"):
        raise PermissionError("admin required")


def best_effort(action) -> None:
    try:
        action()
    except ValueError:
        log.exception("action failed")
