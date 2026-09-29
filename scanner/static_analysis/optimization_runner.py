"""
OptimizationRunner — deterministic Python performance checks built on ``ast``.

Closes the gap between the plan's "optimization scanner" claim and what the
security tools emit. Rules are intentionally conservative (high precision):

  OPT001  DB / network call inside a loop (N+1 pattern): DB-API cursors, Django
          ``Model.objects`` chains, SQLAlchemy sessions, requests/httpx-style clients
  OPT002  String concatenation with ``+=`` inside a loop (quadratic copying)
  OPT003  Nested loops over the same collection (O(n^2))
  OPT004  ``re.<fn>(literal, ...)`` inside a loop (pattern re-resolved each pass)

Python is checked here with ``ast``; JavaScript/TypeScript by ``optimization_js`` (tree-sitter).
Other languages rely on Semgrep / the LLM.
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

# Method names that almost always mean a round trip to a DB (DB-API cursors / connections).
_DB_METHODS = {"execute", "executemany", "fetchone", "fetchall", "fetchmany"}
# Owners whose ``.query()`` / ``.get(Model, id)`` / ``.scalars()`` are ORM sessions, not arbitrary objects.
_DB_OWNERS = {"db", "session", "sess", "conn", "connection", "cursor", "cur", "engine", "database"}
_DB_OWNER_SUFFIXES = ("_session", "_db", "_conn", "_connection", "_cursor")
_SQLA_SESSION_METHODS = {"scalar", "scalars"}
# Django managers: chains rooted at ``Model.objects`` / ``_default_manager``.
_DJANGO_MANAGERS = {"objects", "_default_manager"}
_DJANGO_QUERY_METHODS = {
    "get", "filter", "exclude", "all", "first", "last", "count", "exists", "aggregate",
    "create", "get_or_create", "update_or_create", "earliest", "latest", "in_bulk", "delete", "update",
}
# HTTP clients. Unambiguous owners are always network; ambiguous ones (``session``, ``client``, ...)
# need URL-like evidence because ``session.get("key")`` is usually a dict-style lookup.
_HTTP_OWNERS = {"requests", "httpx", "urllib3", "aiohttp"}
_HTTP_AMBIGUOUS_OWNERS = {"session", "client", "http", "http_client", "api", "api_client"}
_HTTP_AMBIGUOUS_SUFFIXES = ("_client", "_http")
_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "request"}
_URL_FUNCS = {"urlopen", "urlretrieve"}
_URL_KEYWORDS = {"params", "json", "data", "headers", "timeout", "allow_redirects"}
_RE_FUNCS = {"match", "search", "sub", "findall", "fullmatch", "split", "finditer"}

_FIX_SQL = "Batch the work: one query with IN (...)/JOIN, executemany, or a bulk/concurrent request."
_FIX_DJANGO = (
    "Fetch once outside the loop: filter(id__in=...) plus a dict, select_related()/prefetch_related(), "
    "or annotate()/bulk_create()/bulk_update()."
)
_FIX_SQLA = "Load in one query (IN (...), joinedload/selectinload) or use bulk operations instead of per-row queries."


def _chain(node: ast.expr) -> list[str]:
    """Names along a call/attribute chain, root first: ``a.b(c).d()`` -> ['a', 'b', 'd']."""
    names: list[str] = []
    while True:
        if isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, ast.Attribute):
            names.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Name):
            names.append(node.id)
            break
        else:
            break
    return names[::-1]


def _is_db_owner(name: str) -> bool:
    n = name.lower()
    return n in _DB_OWNERS or n.endswith(_DB_OWNER_SUFFIXES)


def _is_ambiguous_http_owner(name: str) -> bool:
    n = name.lower()
    return n in _HTTP_AMBIGUOUS_OWNERS or n.endswith(_HTTP_AMBIGUOUS_SUFFIXES)


def _looks_like_url_call(node: ast.Call) -> bool:
    """URL-like first argument or HTTP-only keyword arguments."""
    if any(kw.arg in _URL_KEYWORDS for kw in node.keywords):
        return True
    if not node.args:
        return False
    arg = node.args[0]
    if isinstance(arg, ast.JoinedStr):
        return True
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value.startswith(("http://", "https://", "/"))
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)):
        return any(isinstance(s, ast.Constant) and isinstance(s.value, str) for s in (arg.left, arg.right))
    leaf = arg.attr if isinstance(arg, ast.Attribute) else arg.id if isinstance(arg, ast.Name) else ""
    leaf = leaf.lower()
    return leaf in {"url", "uri", "endpoint"} or leaf.endswith(("_url", "_uri", "_endpoint"))


def _call_kind(node: ast.Call) -> tuple[str, float, str] | None:
    """Classify a call as a per-iteration round trip: (kind, confidence, suggested_fix)."""
    func = node.func
    if isinstance(func, ast.Name):
        if func.id in _URL_FUNCS:
            return "network", 0.65, _FIX_SQL
        return None
    if not isinstance(func, ast.Attribute):
        return None

    names = _chain(node)
    method = func.attr
    owner = names[-2] if len(names) >= 2 else ""
    upstream = names[:-1]

    if method in _DB_METHODS:
        return "database", 0.65, _FIX_SQL
    if method in _URL_FUNCS:
        return "network", 0.65, _FIX_SQL

    # Django ORM: Model.objects.<...> chains
    manager_at = next((i for i, n in enumerate(upstream) if n in _DJANGO_MANAGERS), None)
    # ``self.objects`` is usually a plain attribute, not a Django manager
    if manager_at is not None and (manager_at, upstream[0]) != (1, "self") and method in _DJANGO_QUERY_METHODS:
        return "database", 0.6, _FIX_DJANGO

    # SQLAlchemy-style: session.query(...).<...>, session.scalars(...), session.get(Model, pk)
    for i, name in enumerate(names[:-1]):
        if name == "query" and i > 0 and _is_db_owner(names[i - 1]):
            return "database", 0.6, _FIX_SQLA
    if method == "query" and _is_db_owner(owner):
        return "database", 0.6, _FIX_SQLA
    if method in _SQLA_SESSION_METHODS and _is_db_owner(owner):
        return "database", 0.6, _FIX_SQLA
    if method == "get" and _is_db_owner(owner) and len(node.args) >= 2:   # session.get(Model, pk)
        return "database", 0.6, _FIX_SQLA

    if method in _HTTP_METHODS and owner:
        if owner.lower() in _HTTP_OWNERS:
            return "network", 0.65, _FIX_SQL
        if _is_ambiguous_http_owner(owner) and _looks_like_url_call(node):
            return "network", 0.6, _FIX_SQL
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
            hit = _call_kind(node)
            if hit:
                kind, confidence, fix = hit
                if self._io_reported:
                    self.generic_visit(node)
                    return
                self._io_reported = True
                self._add(
                    node, f"{kind.capitalize()} call inside loop (N+1)", Severity.MEDIUM, confidence,
                    f"A {kind} call is issued once per iteration, multiplying latency by the loop size.",
                    fix,
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
    """Analyze every Python and JS/TS file under *target*; never raises."""
    from scanner.static_analysis.optimization_js import JS_EXTENSIONS, analyze_js_file  # noqa: PLC0415

    skip = _SKIP_DIRS | (exclude_dirs or set())
    findings: list[Finding] = []
    for path in sorted(target.rglob("*")):
        suffix = path.suffix.lower()
        is_py = suffix == ".py"
        is_js = suffix in JS_EXTENSIONS and not path.name.lower().endswith((".min.js", ".d.ts"))
        if not (is_py or is_js) or not path.is_file():
            continue
        if skip.intersection(path.relative_to(target).parts[:-1]):
            continue
        try:
            findings.extend(analyze_file(path) if is_py else analyze_js_file(path))
        except Exception as exc:  # defensive: one bad file must not kill the scan
            log.warning("Optimizer failed on %s: %s", path, exc)
    return findings
