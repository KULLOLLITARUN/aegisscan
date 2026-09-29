"""
TreeSitterChunker — extracts functions, classes, and methods via Tree-sitter.

Uses manual AST traversal (TreeCursor) compatible with tree-sitter >= 0.23.
The Query API changed significantly across tree-sitter versions; cursor-based
traversal is stable and avoids the language.query() / Query.captures() API
instability.

Falls back to GenericChunker on any parse or import failure (plan §2 rule 6).

Language-string contract:
  The dispatcher passes the EXACT language string from FileInfo.language,
  which is set by V0's FileClassifier using _EXT_TO_LANGUAGE. These strings
  must be kept in sync with the _TS_GRAMMAR_MAP keys below.

  V0 values → chunker keys (must match exactly):
    "Python"      → "Python"
    "JavaScript"  → "JavaScript"
    "TypeScript"  → "TypeScript"
    "Go", "Java", "PHP", "C#" (added later; same exact-match rule)
"""
from __future__ import annotations

import importlib
import logging
from typing import NamedTuple

from scanner.chunking.base import BaseChunker
from scanner.models.chunk import CodeChunk
from scanner.models.file_info import FileInfo

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Grammar registry
# Maps FileInfo.language (exact V0 string) → (pip-package-module, fn-name)
# ---------------------------------------------------------------------------

class _GrammarSpec(NamedTuple):
    module: str       # importable module name
    fn: str           # function that returns the language capsule


_TS_GRAMMAR_MAP: dict[str, _GrammarSpec] = {
    # MUST match V0 FileClassifier._EXT_TO_LANGUAGE values exactly
    "Python":     _GrammarSpec("tree_sitter_python",     "language"),
    "JavaScript": _GrammarSpec("tree_sitter_javascript", "language"),
    "TypeScript": _GrammarSpec("tree_sitter_typescript", "language_typescript"),
    "Go":         _GrammarSpec("tree_sitter_go",         "language"),
    "Java":       _GrammarSpec("tree_sitter_java",       "language"),
    "PHP":        _GrammarSpec("tree_sitter_php",        "language_php"),
    "C#":         _GrammarSpec("tree_sitter_c_sharp",    "language"),
}

# Node types we extract as CodeChunks, per language
_SYMBOL_NODE_TYPES: dict[str, frozenset[str]] = {
    "Python": frozenset({
        "function_definition",
        "class_definition",
    }),
    "JavaScript": frozenset({
        "function_declaration",
        "arrow_function",
        "class_declaration",
        "method_definition",
    }),
    "TypeScript": frozenset({
        "function_declaration",
        "arrow_function",
        "class_declaration",
        "method_definition",
    }),
    "Go": frozenset({"function_declaration", "method_declaration"}),
    "Java": frozenset({
        "class_declaration", "interface_declaration",
        "method_declaration", "constructor_declaration",
    }),
    "PHP": frozenset({"function_definition", "class_declaration", "method_declaration"}),
    "C#": frozenset({
        "class_declaration", "interface_declaration", "struct_declaration",
        "method_declaration", "constructor_declaration",
    }),
}

_NODE_TYPE_TO_SYMBOL_TYPE: dict[str, str] = {
    "function_definition":  "function",
    "function_declaration": "function",
    "arrow_function":       "function",
    "class_definition":     "class",
    "class_declaration":    "class",
    "method_definition":    "method",
    "method_declaration":   "method",
    "constructor_declaration": "method",
    "interface_declaration": "class",
    "struct_declaration":   "class",
}

# Cache: language string → Language object or None if load failed
_grammar_cache: dict[str, object | None] = {}


def _load_grammar(language: str):
    """Load and cache the Tree-sitter Language for *language*. Returns Language or None."""
    if language in _grammar_cache:
        return _grammar_cache[language]

    spec = _TS_GRAMMAR_MAP.get(language)
    if spec is None:
        _grammar_cache[language] = None
        return None

    try:
        from tree_sitter import Language  # noqa: PLC0415
        mod = importlib.import_module(spec.module)
        lang_fn = getattr(mod, spec.fn)
        ts_language = Language(lang_fn())
        _grammar_cache[language] = ts_language
        log.debug("Loaded Tree-sitter grammar for %s", language)
        return ts_language
    except Exception as exc:
        log.warning("Tree-sitter grammar unavailable for %s: %s", language, exc)
        _grammar_cache[language] = None
        return None


def _extract_import_lines(source_lines: list[str]) -> list[str]:
    """Collect top-level import statements from the first lines of source."""
    imports = []
    for line in source_lines:
        stripped = line.strip()
        if stripped.startswith("import ") or stripped.startswith("from "):
            imports.append(stripped)
        elif stripped and not stripped.startswith("#"):
            break
    return imports


def _get_symbol_name(node, source_bytes: bytes) -> str | None:
    """Extract the identifier name from a function/class node."""
    name_node = node.child_by_field_name("name")
    if name_node is not None:
        return source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
    return None


def _walk_symbols(
    node,
    source_bytes: bytes,
    target_types: frozenset[str],
    language: str,
    file_info: FileInfo,
    imports: list[str],
    chunks: list[CodeChunk],
    seen: set[int],
) -> None:
    """Recursively walk the AST, collecting matching symbol nodes."""
    if node.id in seen:
        return

    if node.type in target_types:
        seen.add(node.id)
        line_start = node.start_point[0] + 1   # 0-indexed → 1-indexed
        line_end   = node.end_point[0] + 1
        code       = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
        symbol_name = _get_symbol_name(node, source_bytes)
        symbol_type = _NODE_TYPE_TO_SYMBOL_TYPE.get(node.type, "function")

        chunks.append(
            CodeChunk(
                file_path=file_info.path,
                language=language,
                symbol_name=symbol_name,
                symbol_type=symbol_type,
                line_start=line_start,
                line_end=line_end,
                code=code,
                imports=imports,
            )
        )

    for child in node.named_children:
        _walk_symbols(child, source_bytes, target_types, language, file_info, imports, chunks, seen)


class TreeSitterChunker(BaseChunker):
    """
    Extracts functions, classes, and methods via tree-sitter AST traversal.

    Compatible with tree-sitter >= 0.23 using cursor/child-based traversal
    (avoids the unstable Query API surface across versions).

    On any failure (missing grammar, parse error) returns [] so the dispatcher
    can fall back to GenericChunker.
    """

    def chunk(self, file_info: FileInfo) -> list[CodeChunk]:
        if file_info.is_binary or file_info.is_oversized or not file_info.language:
            return []

        ts_language = _load_grammar(file_info.language)
        if ts_language is None:
            return []

        target_types = _SYMBOL_NODE_TYPES.get(file_info.language, frozenset())
        if not target_types:
            return []

        try:
            from tree_sitter import Parser  # noqa: PLC0415
            source_bytes = file_info.path.read_bytes()
            parser = Parser(ts_language)
            tree = parser.parse(source_bytes)
        except Exception as exc:
            log.warning("Tree-sitter parse failed for %s: %s", file_info.path, exc)
            return []

        source_lines = source_bytes.decode("utf-8", errors="replace").splitlines()
        imports = _extract_import_lines(source_lines)
        language = file_info.language

        chunks: list[CodeChunk] = []
        seen: set[int] = set()

        try:
            _walk_symbols(
                tree.root_node, source_bytes, target_types,
                language, file_info, imports, chunks, seen,
            )
        except Exception as exc:
            log.warning("AST traversal failed for %s: %s", file_info.path, exc)
            return []

        return chunks
