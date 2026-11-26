"""
Tool status — lets each runner say "I did not run" or "I ran incompletely", and why.

Every runner returns ``list[Finding]``, and an empty list used to mean four different things:
nothing found, tool not installed, tool timed out, tool errored. A scan where Semgrep silently
failed then looked exactly like a clean scan, with a better score. Runners now call
``problem(tool, reason)`` on each of those paths, and ``run_all_tools`` collects the reasons into
``ScanResult.static_tool_issues`` so the CLI, the HTML report and the web UI can say so.

The collector is a context variable, so concurrent scans in different server threads do not mix
their reports, and a runner called outside ``collect()`` (a unit test, the benchmark) just logs.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

_current: ContextVar[dict[str, str] | None] = ContextVar("aegisscan_tool_issues", default=None)


def problem(tool: str, reason: str) -> None:
    """Record that *tool* did not run, or ran incompletely, because of *reason*. The first reason
    per tool is kept (a later batch failing the same way adds nothing)."""
    issues = _current.get()
    if issues is not None:
        issues.setdefault(tool, reason)


@contextmanager
def collect() -> Iterator[dict[str, str]]:
    """Collect ``problem()`` calls made inside the block into the yielded dict (tool -> reason).

    Inside an already open ``collect()`` the same dict is shared, so a caller can open one around
    ``run_all_tools`` and still see what it recorded.
    """
    existing = _current.get()
    if existing is not None:
        yield existing
        return
    issues: dict[str, str] = {}
    token = _current.set(issues)
    try:
        yield issues
    finally:
        _current.reset(token)
