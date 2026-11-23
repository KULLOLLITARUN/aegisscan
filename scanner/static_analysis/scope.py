"""Helpers for scanning only a subset of files (``--changed-only`` and ``--changed-since``)."""
from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path

# Windows rejects command lines over 32,767 characters; stay well under it for every platform.
_CMD_BUDGET = 20_000


def batches(paths: Iterable[Path], fixed_len: int = 0) -> Iterator[list[str]]:
    """Group *paths* into lists whose combined length fits one command line."""
    batch: list[str] = []
    used = fixed_len
    for p in paths:
        s = str(p)
        if batch and used + len(s) + 1 > _CMD_BUDGET:
            yield batch
            batch, used = [], fixed_len
        batch.append(s)
        used += len(s) + 1
    if batch:
        yield batch


def within(target: Path, files: Iterable[Path], skip_dirs: Iterable[str]) -> list[Path]:
    """Sorted files that sit under *target* and not inside any of the *skip_dirs* names."""
    skip = set(skip_dirs)
    keep: list[Path] = []
    for f in files:
        try:
            rel = f.relative_to(target)
        except ValueError:
            continue
        if skip.intersection(rel.parts[:-1]):
            continue
        keep.append(f)
    return sorted(keep)
