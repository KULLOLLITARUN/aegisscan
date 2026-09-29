"""
Tree-sitter port of the optimizer rules for JavaScript / TypeScript (.js .jsx .mjs .cjs .ts .tsx).

  OPT001  DB / network call inside a loop (N+1)
            - DB: ``db.query``/``execute``, Mongoose/Sequelize/Prisma/TypeORM/Knex calls
            - network: ``await fetch/axios.get/...`` inside a real loop. Calls inside
              ``items.map(...)`` callbacks are NOT flagged as network N+1 because
              ``Promise.all(items.map(fetch))`` is the recommended concurrent pattern.
  OPT002  ``+=`` string building inside a loop
  OPT003  Nested loop / ``forEach`` over the same collection
  OPT004  ``new RegExp("literal")`` inside a loop

Same conservative, high-precision philosophy as the Python checker. Findings use
``rule_source="aegis-opt"``, category ``performance``. If tree-sitter or a grammar
is unavailable the analyzer returns [] (graceful degradation, plan §2).
"""
from __future__ import annotations

import importlib
import logging
from pathlib import Path

from scanner.models.finding import Finding, Severity

log = logging.getLogger(__name__)

RULE_SOURCE = "aegis-opt"
_MAX_FILE_BYTES = 1_000_000

JS_EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

_GRAMMAR_BY_EXT: dict[str, tuple[str, str]] = {
    ".js": ("tree_sitter_javascript", "language"),
    ".jsx": ("tree_sitter_javascript", "language"),
    ".mjs": ("tree_sitter_javascript", "language"),
    ".cjs": ("tree_sitter_javascript", "language"),
    ".ts": ("tree_sitter_typescript", "language_typescript"),
    ".tsx": ("tree_sitter_typescript", "language_tsx"),
}

_FUNCTION_TYPES = {
    "function_declaration", "function_expression", "function", "arrow_function",
    "method_definition", "generator_function", "generator_function_declaration",
    "class_declaration", "class",
}
_LOOP_TYPES = {"for_statement", "for_in_statement", "while_statement", "do_statement"}
_ITER_METHODS = {
    "forEach", "map", "filter", "reduce", "reduceRight", "flatMap", "some", "every",
    "find", "findIndex", "findLast",
}

# --- call classification ---------------------------------------------------
_NETWORK_FUNCS = {"fetch", "axios", "got", "ky"}
_NETWORK_OWNERS = {"axios", "got", "ky", "superagent", "$http", "$", "jquery"}
_NETWORK_AMBIGUOUS_OWNERS = {"http", "https", "api", "instance"}
_NETWORK_AMBIGUOUS_SUFFIXES = ("client",)
_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "request", "ajax", "getjson"}

_DB_QUERY_OWNERS = {"db", "pool", "client", "connection", "conn", "knex", "sequelize", "database", "pg", "mysql", "trx", "tx"}
_DB_QUERY_METHODS = {"query", "execute", "raw"}
_ORM_METHODS = {
    "findOne", "findById", "findByPk", "findUnique", "findUniqueOrThrow", "findFirst",
    "findFirstOrThrow", "findAll", "findMany", "findOneAndUpdate", "findByIdAndUpdate",
    "findByIdAndDelete", "countDocuments", "updateOne", "deleteOne", "insertOne", "findOrCreate",
}
_REPO_METHODS = {"find", "findOne", "findBy", "findOneBy", "count", "save", "remove", "insert", "update", "delete"}
_PRISMA_ROOTS = {"prisma"}

_FIX_DB = (
    "Batch the reads/writes: one query with IN/$in/`where: { id: { in: ids } }`, an eager-load "
    "(include/populate/relations), or a bulk operation instead of one call per iteration."
)
_FIX_NET = "Run requests concurrently with Promise.all (bounded), or use a bulk endpoint."


def _load_language(ext: str):
    spec = _GRAMMAR_BY_EXT.get(ext)
    if spec is None:
        return None
    key = f"{spec[0]}.{spec[1]}"
    if key in _language_cache:
        return _language_cache[key]
    try:
        from tree_sitter import Language  # noqa: PLC0415
        lang = Language(getattr(importlib.import_module(spec[0]), spec[1])())
    except Exception as exc:  # missing package / ABI mismatch → degrade
        log.debug("JS optimizer grammar unavailable (%s): %s", key, exc)
        lang = None
    _language_cache[key] = lang
    return lang


_language_cache: dict[str, object | None] = {}


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace") if node is not None else ""


def _chain(node) -> list[str]:
    """Names along a call/member chain, root first: ``a.b(c).d()`` -> ['a', 'b', 'd']."""
    names: list[str] = []
    while node is not None:
        t = node.type
        if t == "call_expression":
            node = node.child_by_field_name("function")
        elif t == "member_expression":
            names.append(_text(node.child_by_field_name("property")))
            node = node.child_by_field_name("object")
        elif t in ("await_expression", "parenthesized_expression", "non_null_expression"):
            named = [c for c in node.children if c.is_named]
            node = named[0] if named else None
        elif t in ("identifier", "this"):
            names.append(_text(node))
            break
        else:
            break
    return names[::-1]


def _iter_key(node) -> str | None:
    """Stable key for simple iterables (identifier / member chain)."""
    if node is None:
        return None
    if node.type in ("identifier", "this"):
        return _text(node)
    if node.type == "member_expression":
        base = _iter_key(node.child_by_field_name("object"))
        prop = _text(node.child_by_field_name("property"))
        return f"{base}.{prop}" if base else None
    return None


def _looks_like_url(call) -> bool:
    args = call.child_by_field_name("arguments")
    named = [c for c in args.children if c.is_named] if args is not None else []
    if not named:
        return False
    first = named[0]
    if first.type == "template_string":
        return True
    if first.type == "string":
        s = _text(first).strip("'\"`")
        return s.startswith(("http://", "https://", "/"))
    if first.type == "binary_expression":
        return any(c.type in ("string", "template_string") for c in first.children)
    leaf = _text(first).rsplit(".", 1)[-1].lower()
    return leaf in {"url", "uri", "endpoint"} or leaf.endswith(("url", "uri", "endpoint"))


def _classify_call(call) -> tuple[str, float, str] | None:
    """Classify a call as a per-iteration round trip: (kind, confidence, fix)."""
    func = call.child_by_field_name("function")
    if func is None:
        return None
    names = _chain(call)
    if not names:
        return None

    if func.type == "identifier":
        if names[0] in _NETWORK_FUNCS:
            return "network", 0.65, _FIX_NET
        if names[0] == "knex":
            return "database", 0.6, _FIX_DB
        return None
    if func.type != "member_expression" or len(names) < 2:
        return None

    method, owner = names[-1], names[-2]
    lowered_owner = owner.lower()

    if names[0] == "knex":
        return "database", 0.6, _FIX_DB
    if any(n in _PRISMA_ROOTS for n in names[:-1]):
        return "database", 0.65, _FIX_DB
    if method in _ORM_METHODS:
        return "database", 0.6, _FIX_DB
    if lowered_owner.endswith(("repository", "repo")) and method in _REPO_METHODS:
        return "database", 0.6, _FIX_DB
    if method in _DB_QUERY_METHODS and lowered_owner in _DB_QUERY_OWNERS:
        return "database", 0.65, _FIX_DB

    if method.lower() in _HTTP_METHODS:
        if lowered_owner in _NETWORK_OWNERS:
            return "network", 0.65, _FIX_NET
        if (
            lowered_owner in _NETWORK_AMBIGUOUS_OWNERS or lowered_owner.endswith(_NETWORK_AMBIGUOUS_SUFFIXES)
        ) and _looks_like_url(call):
            return "network", 0.6, _FIX_NET
    return None


class _Walker:
    def __init__(self, path: Path, source: bytes) -> None:
        self.path = path
        self.lines = source.decode("utf-8", errors="replace").splitlines()
        self.findings: list[Finding] = []
        self._io_reported = False

    # -- finding helper --------------------------------------------------
    def _add(self, node, issue: str, severity: Severity, confidence: float, explanation: str, fix: str) -> None:
        start = node.start_point[0] + 1
        end = node.end_point[0] + 1
        self.findings.append(Finding(
            file_path=self.path,
            issue_type=issue,
            category="performance",
            severity=severity,
            confidence=confidence,
            line_start=start,
            line_end=end,
            evidence="\n".join(self.lines[start - 1:end])[:300],
            explanation=explanation,
            suggested_fix=fix,
            rule_source=RULE_SOURCE,
        ))

    # -- traversal -------------------------------------------------------
    # ``loops`` is a list of (key, is_real_loop) for enclosing loops / iteration callbacks.
    def visit(self, node, loops: list[tuple[str | None, bool]], str_names: set[str]) -> None:
        t = node.type
        if t in _FUNCTION_TYPES:
            for child in node.children:
                self.visit(child, [], set())
            return
        if t in _LOOP_TYPES:
            self._visit_loop(node, loops, str_names)
            return
        if t == "variable_declarator":
            value = node.child_by_field_name("value")
            name = node.child_by_field_name("name")
            if value is not None and name is not None and name.type == "identifier" \
                    and value.type in ("string", "template_string"):
                str_names.add(_text(name))
        elif t == "augmented_assignment_expression" and loops:
            self._check_concat(node, str_names)
        elif t == "new_expression" and loops:
            self._check_regex(node)
        elif t == "call_expression":
            if self._visit_call(node, loops, str_names):
                return
        for child in node.children:
            self.visit(child, loops, str_names)

    def _visit_loop(self, node, loops, str_names) -> None:
        key = None
        if node.type == "for_in_statement":
            is_of = any(not c.is_named and c.type == "of" for c in node.children)
            if is_of:
                key = _iter_key(node.child_by_field_name("right"))
                if key is not None and any(k == key for k, _ in loops):
                    self._nested(node, key)
        body = node.child_by_field_name("body")
        if not loops:
            self._io_reported = False
        for child in node.children:
            if body is not None and child == body:
                self.visit(child, loops + [(key, True)], str_names)
            else:
                self.visit(child, loops, str_names)

    def _nested(self, node, key: str) -> None:
        self._add(
            node, "Nested loop over same collection (O(n²))", Severity.MEDIUM, 0.7,
            f"The collection '{key}' is iterated inside another loop over itself, "
            "giving quadratic time on large inputs.",
            "Index the collection once (Map/Set) or sort and use two pointers.",
        )

    def _visit_call(self, call, loops, str_names) -> bool:
        """Handle iteration callbacks and round-trip calls. Returns True if children were visited."""
        func = call.child_by_field_name("function")
        callback = None
        key: str | None = None
        if func is not None and func.type == "member_expression":
            method = _text(func.child_by_field_name("property"))
            if method in _ITER_METHODS:
                args = call.child_by_field_name("arguments")
                first = next((c for c in args.children if c.is_named), None) if args is not None else None
                if first is not None and first.type in _FUNCTION_TYPES:
                    callback = first
                    key = _iter_key(func.child_by_field_name("object"))
                    if method == "forEach" and key is not None and any(k == key for k, _ in loops):
                        self._nested(call, key)

        if loops:
            hit = _classify_call(call)
            if hit:
                kind, confidence, fix = hit
                real_loop = any(is_real for _, is_real in loops)
                awaited = call.parent is not None and call.parent.type == "await_expression"
                # network in map/forEach callbacks is usually concurrent, so require an awaited call in a real loop
                if kind == "network" and not (real_loop and awaited):
                    hit = None
            if hit and not self._io_reported:
                self._io_reported = True
                self._add(
                    call, f"{kind.capitalize()} call inside loop (N+1)", Severity.MEDIUM, confidence,
                    f"A {kind} call is issued once per iteration, multiplying latency by the loop size.",
                    fix,
                )

        if callback is None:
            return False
        if not loops:
            self._io_reported = False
        for child in call.children:
            if child.type != "arguments":
                self.visit(child, loops, str_names)
                continue
            for arg in child.children:
                if arg == callback:
                    # the callback body runs once per element: keep the loop context, fresh string scope
                    for sub in arg.children:
                        self.visit(sub, loops + [(key, False)], set())
                else:
                    self.visit(arg, loops, str_names)
        return True

    def _check_concat(self, node, str_names) -> None:
        left = node.child_by_field_name("left")
        op = node.child_by_field_name("operator")
        if op is not None and _text(op) == "+=" and left is not None and left.type == "identifier" \
                and _text(left) in str_names:
            self._add(
                node, "String concatenation in loop", Severity.LOW, 0.7,
                f"'{_text(left)}' is a string built with += inside a loop; each step may copy the string.",
                "Collect parts in an array and use parts.join('').",
            )

    def _check_regex(self, node) -> None:
        ctor = node.child_by_field_name("constructor")
        args = node.child_by_field_name("arguments")
        first = next((c for c in args.children if c.is_named), None) if args is not None else None
        if ctor is not None and _text(ctor) == "RegExp" and first is not None and first.type == "string":
            self._add(
                node, "Regex pattern re-resolved in loop", Severity.LOW, 0.5,
                "new RegExp() with a literal pattern inside a loop recompiles the pattern on every iteration.",
                "Hoist `const re = new RegExp(...)` (or a /literal/) above the loop.",
            )


def analyze_js_file(path: Path) -> list[Finding]:
    """Analyze one JS/TS file; returns [] on any failure or if tree-sitter is unavailable."""
    ext = path.suffix.lower()
    lang = _load_language(ext)
    if lang is None:
        return []
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return []
        source = path.read_bytes()
        from tree_sitter import Parser  # noqa: PLC0415
        tree = Parser(lang).parse(source)
        walker = _Walker(path, source)
        walker.visit(tree.root_node, [], set())
        return walker.findings
    except (OSError, RecursionError, ValueError) as exc:
        log.debug("JS optimizer skipped %s: %s", path, exc)
        return []
