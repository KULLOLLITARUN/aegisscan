"""
Per-project configuration, read from ``.aegisscan.toml`` in the scan target.

    # .aegisscan.toml
    exclude_dirs = ["tests", "examples"]   # extra directory names skipped by static tools
    exclude_files = [".env", "*.pem", "config/local.*"]   # file patterns skipped by every stage

Missing or malformed files fall back to defaults (graceful degradation, plan §2
rule 6) — a bad config must never abort a scan.
"""
from __future__ import annotations

import fnmatch
import logging
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

CONFIG_FILENAME = ".aegisscan.toml"


@dataclass(frozen=True)
class ScanConfig:
    exclude_dirs: frozenset[str] = field(default_factory=frozenset)
    exclude_files: tuple[str, ...] = ()

    def is_file_excluded(self, rel_path: str) -> bool:
        """True if *rel_path* (relative to the target) matches an ``exclude_files`` pattern.

        A pattern without ``/`` is matched against the file name (``.env``, ``*.pem``); one with
        ``/`` is matched against the whole relative path (``config/local.*``). Case-insensitive.
        """
        if not self.exclude_files:
            return False
        rel = rel_path.replace("\\", "/").removeprefix("./").lower()
        name = rel.rsplit("/", 1)[-1]
        for pat in self.exclude_files:
            pat = pat.replace("\\", "/").lower()
            if fnmatch.fnmatchcase(rel if "/" in pat else name, pat):
                return True
        return False


def load_config(target: Path) -> ScanConfig:
    path = target / CONFIG_FILENAME
    if not path.is_file():
        return ScanConfig()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        log.warning("Ignoring invalid %s: %s", path, exc)
        return ScanConfig()

    raw = data.get("exclude_dirs", [])
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        log.warning("%s: exclude_dirs must be a list of strings — ignored", path)
        raw = []
    files = data.get("exclude_files", [])
    if not isinstance(files, list) or not all(isinstance(x, str) for x in files):
        log.warning("%s: exclude_files must be a list of strings — ignored", path)
        files = []
    return ScanConfig(exclude_dirs=frozenset(raw), exclude_files=tuple(files))
