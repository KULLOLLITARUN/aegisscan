"""
OptimizationRunner — deterministic Python performance checks built on ``ast``.

Closes the gap between the plan's "optimization scanner" claim and what the
security tools emit. Rules are intentionally conservative (high precision):

  OPT001  DB / network call inside a loop (N+1 pattern)
  OPT002  String concatenation with ``+=`` inside a loop (quadratic copying)
  OPT003  Nested loops over the same collection (O(n^2))
  OPT004  ``re.<fn>(literal, ...)`` inside a loop (pattern re-resolved each pass)

Only Python is covered; other languages rely on Semgrep / the LLM.
Findings use ``rule_source="aegis-opt"`` and category ``performance``.
"""
from __future__ import annotations

import ast
import logging
from pathlib import Path

from scanner.models.finding import Finding, Severity

log = logging.getLogger(__name__)

RULE_SOURCE = "aegis-opt"

_SKIP_DIRS = {".venv", "venv", "node_modules", "__pycache__", "dist", ".git", "build", "site-packages"}
_MAX_FILE_BYTES = 1_000_000

# Method names that almost always mean a round trip to a DB or remote service.
_DB_METHODS = {"execute", "executemany", "fetchone", "fetchall", "fetchmany", "query"}
_HTTP_OWNERS = {"requests", "httpx", "session", "client"}
_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head"}
_RE_FUNCS = {"match", "search", "sub", "findall", "fullmatch", "split", "finditer"}


def _call_kind(node: ast.Call) -> str | None:
    func = node.func
    if not isinstance(func, ast.Attribute):
        return None
    if func.attr in _DB_METHODS:
        return "database"
    owner = func.value
    if func.attr in _HTTP_METHODS and isinstance(owner, ast.Name) and owner.id.lower() in _HTTP_OWNERS:
        return "network"
    return None


def _is_re_literal_call(node: ast.Call) -> bool:
    func = node.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr in _RE_FUNCS
        and isinstance(func.value, ast.Name)
        and func.value.id == "re"
        and bool(node.args)
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    )


def _iter_key(node: ast.expr) -> str | None:
    """Stable key for simple iterables (names / attribute chains) so nested loops can be compared."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _iter_key(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _snippet(lines: list[str], start: int, end: int) -> str:
    return "\n".join(lines[start - 1:end])[:300]


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: Path, lines: list[str]) -> None:
        self.path = path
        self.lines = lines
        self.findings: list[Finding] = []
        self._loop_iters: list[str | None] = []   # iterable keys of enclosing loops
        self._str_names: set[str] = set()
        self._io_reported = False

    def _add(self, node: ast.AST, issue: str, severity: Severity, confidence: float,
             explanation: str, fix: str) -> None:
        start = getattr(node, "lineno", 1)
        end = getattr(node, "end_lineno", start) or start
        self.findings.append(Finding(
            file_path=self.path,
            issue_type=issue,
            category="performance",
            severity=severity,
            confidence=confidence,
            line_start=start,
            line_end=end,
            evidence=_snippet(self.lines, start, end),
            explanation=explanation,
            suggested_fix=fix,
            rule_source=RULE_SOURCE,
        ))

    def _push(self, key: str | None) -> None:
        if not self._loop_iters:
            self._io_reported = False   # new outermost loop: allow one N+1 report
        self._loop_iters.append(key)

    def _pop(self) -> None:
        self._loop_iters.pop()

    @property
    def _in_loop(self) -> bool:
        return bool(self._loop_iters)

    # A new function/class body starts with a clean loop context.
    def _visit_scope(self, node: ast.AST) -> None:
        saved, saved_str = self._loop_iters, self._str_names
        self._loop_iters, self._str_names = [], set()
        self.generic_visit(node)
        self._loop_iters, self._str_names = saved, saved_str

    visit_FunctionDef = visit_AsyncFunctionDef = visit_Lambda = visit_ClassDef = _visit_scope

    def visit_For(self, node: ast.For) -> None:
        key = _iter_key(node.iter)
        if key is not None and key in self._loop_iters:
            self._add(
                node, "Nested loop over same collection (O(n²))", Severity.MEDIUM, 0.7,
                f"The collection '{key}' is iterated inside another loop over itself, "
                "giving quadratic time on large inputs.",
                "Index the collection once (dict/set) or use sorting / two pointers.",
            )
        self.visit(node.iter)
        self._push(key)
        for child in node.body + node.orelse:
            self.visit(child)
        self._pop()

    def visit_While(self, node: ast.While) -> None:
        self.visit(node.test)
        self._push(None)
        for child in node.body + node.orelse:
            self.visit(child)
        self._pop()

    def _visit_comprehension(self, node: ast.AST) -> None:
        # Comprehensions are loops too; query calls inside them are just as costly.
        generators = node.generators  # type: ignore[attr-defined]
        for gen in generators:
            self._push(_iter_key(gen.iter))
        self.generic_visit(node)
        for _ in generators:
            self._pop()

    visit_ListComp = visit_SetComp = visit_DictComp = visit_GeneratorExp = _visit_comprehension

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self._str_names.add(t.id)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if (
            self._in_loop
            and isinstance(node.op, ast.Add)
            and isinstance(node.target, ast.Name)
            and node.target.id in self._str_names
        ):
            self._add(
                node, "String concatenation in loop", Severity.LOW, 0.7,
                f"'{node.target.id}' is a string built with += inside a loop; each step copies the string.",
                "Collect parts in a list and use ''.join(parts).",
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if self._in_loop:
            kind = _call_kind(node)
            if kind:
                if self._io_reported:
                    self.generic_visit(node)
                    return
                self._io_reported = True
                self._add(
                    node, f"{kind.capitalize()} call inside loop (N+1)", Severity.MEDIUM, 0.65,
                    f"A {kind} call is issued once per iteration, multiplying latency by the loop size.",
                    "Batch the work: one query with IN (...)/JOIN, executemany, or a bulk/concurrent request.",
                )
            elif _is_re_literal_call(node):
                self._add(
                    node, "Regex pattern re-resolved in loop", Severity.LOW, 0.5,
                    "re.<fn>() with a literal pattern inside a loop pays a cache lookup on every iteration.",
                    "Hoist `pattern = re.compile(...)` above the loop.",
                )
        self.generic_visit(node)


def analyze_file(path: Path) -> list[Finding]:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return []
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, OSError, ValueError) as exc:
        log.debug("Optimizer skipped %s: %s", path, exc)
        return []
    visitor = _Visitor(path, source.splitlines())
    visitor.visit(tree)
    return visitor.findings


def run_optimizer(target: Path, exclude_dirs: set[str] | None = None) -> list[Finding]:
    """Analyze every ``.py`` file under *target*; never raises."""
    skip = _SKIP_DIRS | (exclude_dirs or set())
    findings: list[Finding] = []
    for path in sorted(target.rglob("*.py")):
        if skip.intersection(path.relative_to(target).parts[:-1]):
            continue
        try:
            findings.extend(analyze_file(path))
        except Exception as exc:  # defensive: one bad file must not kill the scan
            log.warning("Optimizer failed on %s: %s", path, exc)
    return findings
