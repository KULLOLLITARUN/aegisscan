"""
GitDiffScanner — Incremental scanning helper for V6.

Identifies modified, untracked, or staged files using `git status` / `git diff`.
Enables `--changed-only` scanning mode to drastically speed up CI/CD execution.
"""
from __future__ import annotations

import logging
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)


def get_changed_files(target_dir: Path) -> set[Path] | None:
    """
    Get relative paths of modified, staged, or untracked files in target_dir.

    Returns:
        Set of resolved absolute Path objects, or None if git is not available / target is not a repo.
    """
    target_dir = target_dir.resolve()

    try:
        # Check if target_dir is inside a git repo
        check = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=str(target_dir),
            capture_output=True,
            text=True,
            timeout=5,
        )
        if check.returncode != 0 or check.stdout.strip() != "true":
            log.warning("Target directory %s is not a git repository", target_dir)
            return None

        changed: set[Path] = set()

        # 1. Staged and unstaged changes + untracked files (status --porcelain)
        proc_status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(target_dir),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc_status.returncode == 0:
            for line in proc_status.stdout.splitlines():
                if not line.strip():
                    continue
                # Line format: ' M path/to/file.py' or '?? path/to/file.py'
                filepath_str = line[3:].strip()
                # Handle renamed files 'R  old -> new'
                if " -> " in filepath_str:
                    filepath_str = filepath_str.split(" -> ")[-1]
                p = (target_dir / filepath_str).resolve()
                if p.exists() and p.is_file():
                    changed.add(p)

        # 2. Changes against HEAD (commit diff)
        proc_diff = subprocess.run(
            ["git", "diff", "--name-only", "HEAD"],
            cwd=str(target_dir),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc_diff.returncode == 0:
            for line in proc_diff.stdout.splitlines():
                line = line.strip()
                if line:
                    p = (target_dir / line).resolve()
                    if p.exists() and p.is_file():
                        changed.add(p)

        return changed

    except Exception as exc:
        log.warning("Failed to determine git changed files: %s", exc)
        return None
