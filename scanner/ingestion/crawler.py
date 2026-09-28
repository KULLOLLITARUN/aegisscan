"""
WorkspaceCrawler — walks a directory tree with pathlib and respects .gitignore.

Design rules (plan §2):
- Pure discovery layer: no imports of Semgrep, Groq, security, or optimization.
- No config.py in V0; hardcoded defaults live here as named constants.
- Graceful degradation: PermissionError on any entry is logged and skipped —
  the crawler always returns a valid (possibly partial) result.
- Nested .gitignore: specs accumulate as we descend so each directory's rules
  apply to everything beneath it.
- Symlinks are skipped to prevent cycles and out-of-tree traversal.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

import pathspec

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hardcoded defaults  (no config.py until a real config need exists — V1+)
# ---------------------------------------------------------------------------

#: Directories always excluded regardless of .gitignore rules.
ALWAYS_IGNORED_DIRS: frozenset[str] = frozenset(
    {
        ".git", ".hg", ".svn",
        "node_modules",
        "venv", ".venv", "env",
        "__pycache__",
        "dist", "build",
        ".tox", ".eggs",
        ".mypy_cache", ".pytest_cache", ".ruff_cache",
        ".next", ".nuxt", ".output",
        "vendor", "bower_components",
        ".gradle", "target",        # Java / Rust build output
        "out",
        ".idea", ".vscode",
        "coverage", "htmlcov",
        "site-packages",
    }
)


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class CrawlResult:
    """Paths discovered by the crawler plus run statistics."""

    root: Path
    discovered: list[Path] = field(default_factory=list)
    ignored_count: int = 0      # dirs/files excluded (no deep-count inside dirs)

    @property
    def total_seen(self) -> int:
        return len(self.discovered) + self.ignored_count


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_gitignore(directory: Path) -> pathspec.PathSpec | None:
    """Parse the .gitignore in *directory* and return a PathSpec, or None."""
    gitignore = directory / ".gitignore"
    if not gitignore.is_file():
        return None
    try:
        text = gitignore.read_text(encoding="utf-8", errors="replace")
        # Strip blank lines and pure-comment lines for cleaner parsing
        lines = [
            ln for ln in text.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        return pathspec.PathSpec.from_lines("gitignore", lines)
    except OSError as exc:
        log.warning("Could not read %s: %s", gitignore, exc)
        return None


def _is_gitignored(
    path: Path,
    specs: list[tuple[Path, pathspec.PathSpec]],
) -> bool:
    """Return True if *path* matches any accumulated .gitignore spec."""
    for spec_root, spec in specs:
        try:
            rel = path.relative_to(spec_root)
        except ValueError:
            continue
        rel_str = rel.as_posix()
        # pathspec expects trailing slash for directories
        if path.is_dir():
            rel_str += "/"
        if spec.match_file(rel_str):
            return True
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class WorkspaceCrawler:
    """
    Walks a target directory, returning every non-ignored regular file.

    Usage::

        result = WorkspaceCrawler(Path("./my-repo")).crawl()
        for path in result.discovered:
            info = FileClassifier().classify(path)
    """

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def crawl(self) -> CrawlResult:
        """Walk the tree and return a CrawlResult."""
        result = CrawlResult(root=self.root)
        for item in self._walk(self.root, gitignore_specs=[]):
            if item is None:
                result.ignored_count += 1
            else:
                result.discovered.append(item)
        return result

    # ------------------------------------------------------------------
    # Internal walk — yields Path for discovered files, None for ignored
    # ------------------------------------------------------------------

    def _walk(
        self,
        directory: Path,
        gitignore_specs: list[tuple[Path, pathspec.PathSpec]],
    ) -> Iterator[Path | None]:
        # Accumulate .gitignore rules at this level
        local_spec = _load_gitignore(directory)
        if local_spec is not None:
            gitignore_specs = [*gitignore_specs, (directory, local_spec)]

        try:
            entries = sorted(directory.iterdir())
        except PermissionError as exc:
            log.warning("Permission denied reading directory %s: %s", directory, exc)
            return

        for entry in entries:
            # Skip symlinks to avoid cycles / out-of-tree traversal
            if entry.is_symlink():
                log.debug("Skipping symlink: %s", entry)
                yield None
                continue

            # Hard ignore-list for well-known non-source directories
            if entry.is_dir() and entry.name in ALWAYS_IGNORED_DIRS:
                log.debug("Skipping always-ignored dir: %s", entry)
                yield None
                continue

            # .gitignore rules (nested, accumulated from root downward)
            if _is_gitignored(entry, gitignore_specs):
                log.debug("Gitignored: %s", entry)
                yield None
                continue

            if entry.is_dir():
                yield from self._walk(entry, gitignore_specs)
            elif entry.is_file():
                yield entry
            # Anything else (sockets, devices, etc.) is silently skipped
