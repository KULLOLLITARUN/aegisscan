"""Tests for WorkspaceCrawler.

Covers (per plan §4 V0):
  - Normal discovery
  - Nested .gitignore files
  - Empty repository
  - PermissionError on a directory
  - Symlinks (skipped)
  - Unicode / unusual filenames
  - Always-ignored directories (.git, node_modules, __pycache__, etc.)
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from scanner.ingestion.crawler import ALWAYS_IGNORED_DIRS, WorkspaceCrawler


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(path: Path, content: str = "") -> Path:
    """Create *path* (and parents) with *content*."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Basic discovery
# ---------------------------------------------------------------------------

def test_discovers_files(tmp_path: Path) -> None:
    _write(tmp_path / "main.py", "print('hello')")
    _write(tmp_path / "README.md", "# Readme")
    _write(tmp_path / "src" / "utils.py", "pass")

    result = WorkspaceCrawler(tmp_path).crawl()

    paths = {p.name for p in result.discovered}
    assert paths == {"main.py", "README.md", "utils.py"}


def test_empty_repo(tmp_path: Path) -> None:
    result = WorkspaceCrawler(tmp_path).crawl()
    assert result.discovered == []
    assert result.ignored_count == 0


# ---------------------------------------------------------------------------
# Always-ignored directories
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("dir_name", ["node_modules", "__pycache__", ".git", "venv", "dist"])
def test_always_ignored_dirs_excluded(tmp_path: Path, dir_name: str) -> None:
    _write(tmp_path / dir_name / "secret.py", "bad")
    _write(tmp_path / "main.py", "good")

    result = WorkspaceCrawler(tmp_path).crawl()

    assert len(result.discovered) == 1
    assert result.discovered[0].name == "main.py"
    assert result.ignored_count >= 1


def test_always_ignored_dirs_constant_completeness() -> None:
    """Smoke-test that the frozenset is non-empty and contains key entries."""
    assert ".git" in ALWAYS_IGNORED_DIRS
    assert "node_modules" in ALWAYS_IGNORED_DIRS
    assert "__pycache__" in ALWAYS_IGNORED_DIRS
    assert "venv" in ALWAYS_IGNORED_DIRS


# ---------------------------------------------------------------------------
# .gitignore support
# ---------------------------------------------------------------------------

def test_root_gitignore_excludes_files(tmp_path: Path) -> None:
    _write(tmp_path / ".gitignore", "*.log\nbuild/\n")
    _write(tmp_path / "app.py", "code")
    _write(tmp_path / "error.log", "log data")
    _write(tmp_path / "build" / "output.js", "compiled")

    result = WorkspaceCrawler(tmp_path).crawl()

    names = {p.name for p in result.discovered}
    assert "app.py" in names
    assert "error.log" not in names
    assert "output.js" not in names


def test_nested_gitignore(tmp_path: Path) -> None:
    """A .gitignore inside a subdirectory must apply only to that subtree."""
    _write(tmp_path / ".gitignore", "*.log\n")
    _write(tmp_path / "app.py", "top-level code")
    _write(tmp_path / "app.log", "top-level log")          # excluded by root gitignore

    sub = tmp_path / "subpackage"
    _write(sub / ".gitignore", "*.tmp\n")
    _write(sub / "module.py", "sub code")
    _write(sub / "scratch.tmp", "temp file")               # excluded by nested gitignore
    _write(sub / "notes.log", "sub log")                   # excluded by root gitignore

    result = WorkspaceCrawler(tmp_path).crawl()
    names = {p.name for p in result.discovered}

    assert "app.py" in names
    assert "module.py" in names
    assert "app.log" not in names
    assert "scratch.tmp" not in names
    assert "notes.log" not in names


def test_gitignore_negation(tmp_path: Path) -> None:
    """Negation patterns (!pattern) should un-ignore a file."""
    _write(tmp_path / ".gitignore", "*.cfg\n!important.cfg\n")
    _write(tmp_path / "ignored.cfg", "ignore me")
    _write(tmp_path / "important.cfg", "keep me")
    _write(tmp_path / "main.py", "code")

    result = WorkspaceCrawler(tmp_path).crawl()
    names = {p.name for p in result.discovered}

    # pathspec handles negation natively
    assert "main.py" in names
    assert "ignored.cfg" not in names
    assert "important.cfg" in names


def test_empty_gitignore(tmp_path: Path) -> None:
    """An empty .gitignore must not exclude anything — main.py must be discovered.
    The .gitignore file itself is a legitimate file and is also discovered."""
    _write(tmp_path / ".gitignore", "")
    _write(tmp_path / "main.py", "code")

    result = WorkspaceCrawler(tmp_path).crawl()
    names = {p.name for p in result.discovered}
    assert "main.py" in names   # no false exclusions
    assert result.ignored_count == 0


# ---------------------------------------------------------------------------
# PermissionError
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform == "win32", reason="chmod is unreliable on Windows for directories")
def test_permission_error_on_directory(tmp_path: Path) -> None:
    """A directory we cannot read should be skipped, not crash the crawler."""
    _write(tmp_path / "accessible.py", "code")
    locked = tmp_path / "locked_dir"
    locked.mkdir()
    _write(locked / "hidden.py", "secret")

    # Remove read+execute permission
    locked.chmod(0o000)
    try:
        result = WorkspaceCrawler(tmp_path).crawl()
        names = {p.name for p in result.discovered}
        assert "accessible.py" in names
        assert "hidden.py" not in names  # locked dir was skipped
    finally:
        locked.chmod(stat.S_IRWXU)  # restore so tmp_path cleanup works


# ---------------------------------------------------------------------------
# Symlinks
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform == "win32", reason="symlinks require elevated privileges on Windows")
def test_symlinks_are_skipped(tmp_path: Path) -> None:
    real = tmp_path / "real.py"
    real.write_text("real code", encoding="utf-8")
    link = tmp_path / "link.py"
    link.symlink_to(real)

    result = WorkspaceCrawler(tmp_path).crawl()
    names = {p.name for p in result.discovered}

    assert "real.py" in names
    assert "link.py" not in names
    assert result.ignored_count >= 1


# ---------------------------------------------------------------------------
# Unicode / unusual filenames
# ---------------------------------------------------------------------------

def test_unicode_filenames(tmp_path: Path) -> None:
    """Crawler must handle Unicode filenames without crashing."""
    _write(tmp_path / "日本語.py", "# Japanese filename")
    _write(tmp_path / "café.py", "# Accented filename")
    _write(tmp_path / "αβγδ.py", "# Greek filename")

    result = WorkspaceCrawler(tmp_path).crawl()
    names = {p.name for p in result.discovered}

    assert "日本語.py" in names
    assert "café.py" in names
    assert "αβγδ.py" in names


def test_filename_with_spaces(tmp_path: Path) -> None:
    _write(tmp_path / "my module.py", "code")
    _write(tmp_path / "another file.txt", "text")

    result = WorkspaceCrawler(tmp_path).crawl()
    names = {p.name for p in result.discovered}
    assert "my module.py" in names
    assert "another file.txt" in names


def test_deeply_nested_structure(tmp_path: Path) -> None:
    """Crawler must descend arbitrarily deep."""
    deep = tmp_path / "a" / "b" / "c" / "d" / "e"
    _write(deep / "deep.py", "deep code")

    result = WorkspaceCrawler(tmp_path).crawl()
    assert len(result.discovered) == 1
    assert result.discovered[0].name == "deep.py"


# ---------------------------------------------------------------------------
# Statistics / CrawlResult
# ---------------------------------------------------------------------------

def test_ignored_count_tracks_excluded_dirs(tmp_path: Path) -> None:
    _write(tmp_path / "node_modules" / "index.js", "npm")
    _write(tmp_path / "main.py", "code")

    result = WorkspaceCrawler(tmp_path).crawl()
    assert len(result.discovered) == 1
    assert result.ignored_count >= 1  # at least the node_modules dir


def test_total_seen_is_consistent(tmp_path: Path) -> None:
    _write(tmp_path / ".gitignore", "*.log\n")
    _write(tmp_path / "main.py", "code")
    _write(tmp_path / "error.log", "log")

    result = WorkspaceCrawler(tmp_path).crawl()
    assert result.total_seen == len(result.discovered) + result.ignored_count
