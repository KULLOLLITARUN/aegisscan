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


def get_changed_files(target_dir: Path, since: str | None = None) -> set[Path] | None:
    """
    Get the modified, staged, or untracked files in target_dir.

    With *since* (a branch, tag or commit), files changed between that ref and ``HEAD`` are
    included as well, so a CI run on a clean checkout still sees what a pull request or push changed.
    The comparison is against the merge base (``since...HEAD``), like a pull request diff.

    Returns:
        Set of resolved absolute Path objects, or None if git is not available / target is not a repo /
        *since* is not a commit in this repository (callers then scan everything rather than nothing).
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

        if since is not None:
            if since.startswith("-"):  # would be read as a git option, not a ref
                log.warning("--changed-since %r is not a valid ref; scanning everything instead", since)
                return None
            verify = subprocess.run(
                ["git", "rev-parse", "--verify", "--quiet", f"{since}^{{commit}}"],
                cwd=str(target_dir),
                capture_output=True,
                text=True,
                timeout=5,
            )
            if verify.returncode != 0:
                log.warning("--changed-since %r is not a known commit here; scanning everything instead", since)
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

        if since is not None:
            # --relative keeps paths relative to target_dir, which may be a subfolder of the repo.
            proc_since = subprocess.run(
                ["git", "diff", "--name-only", "--relative", "--diff-filter=ACMR", f"{since}...HEAD"],
                cwd=str(target_dir),
                capture_output=True,
                text=True,
                timeout=30,
            )
            if proc_since.returncode != 0:
                log.warning("git diff against %r failed (%s); scanning everything instead",
                            since, proc_since.stderr.strip()[:200])
                return None
            for line in proc_since.stdout.splitlines():
                line = line.strip()
                if line:
                    p = (target_dir / line).resolve()
                    if p.exists() and p.is_file():
                        changed.add(p)

        return changed

    except Exception as exc:
        log.warning("Failed to determine git changed files: %s", exc)
        return None
