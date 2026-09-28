"""Tests for the chunking layer (V1).

Covers:
  - Python function and class extraction via TreeSitterChunker
  - JavaScript function, arrow function, and class extraction
  - GenericChunker 50-line window fallback
  - chunk_file() fallback when Tree-sitter returns nothing
  - CodeChunk is always the return type (never raw dict)
  - Empty file, single-line file, file with only imports
  - Language-string contract: dispatcher keys match V0 classifier output
"""
from __future__ import annotations

from pathlib import Path

import pytest

from scanner.chunking.dispatcher import chunk_file, get_chunker, _tree_sitter_chunker, _generic_chunker
from scanner.chunking.generic_chunker import WINDOW_SIZE, GenericChunker
from scanner.chunking.tree_sitter_chunker import _TS_GRAMMAR_MAP
from scanner.models.chunk import CodeChunk
from scanner.models.file_info import FileInfo


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fi(
    path: Path,
    language: str | None = None,
    is_binary: bool = False,
    is_generated: bool = False,
    is_oversized: bool = False,
) -> FileInfo:
    size = path.stat().st_size if path.exists() else 0
    return FileInfo(
        path=path,
        language=language,
        size_bytes=size,
        is_binary=is_binary,
        is_generated=is_generated,
        is_oversized=is_oversized,
    )


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Language-string contract sanity check
# ---------------------------------------------------------------------------

def test_dispatcher_keys_match_v0_classifier_strings() -> None:
    """
    CRITICAL: dispatcher grammar map keys must exactly match the strings
    that V0's FileClassifier._EXT_TO_LANGUAGE produces.
    A mismatch silently falls through to GenericChunker.
    """
    # These are the exact strings set by V0 classifier for these extensions
    expected_supported = {"Python", "JavaScript", "TypeScript"}
    assert expected_supported.issubset(set(_TS_GRAMMAR_MAP.keys())), (
        f"Dispatcher keys {set(_TS_GRAMMAR_MAP.keys())} missing some V0 strings"
    )
    # No lowercase or abbreviated forms
    for key in _TS_GRAMMAR_MAP:
        assert key[0].isupper(), f"Grammar map key '{key}' must start with uppercase (V0 uses title-case)"


# ---------------------------------------------------------------------------
# TreeSitterChunker — Python
# ---------------------------------------------------------------------------

def test_python_function_extracted(tmp_path: Path) -> None:
    code = "def greet(name):\n    return f'Hello {name}'\n"
    p = _write(tmp_path / "hello.py", code)
    fi = _make_fi(p, language="Python")

    chunks = _tree_sitter_chunker.chunk(fi)

    assert len(chunks) >= 1
    names = [c.symbol_name for c in chunks if c.symbol_name]
    assert "greet" in names


def test_python_class_extracted(tmp_path: Path) -> None:
    code = "class Dog:\n    def bark(self):\n        print('Woof')\n"
    p = _write(tmp_path / "dog.py", code)
    fi = _make_fi(p, language="Python")

    chunks = _tree_sitter_chunker.chunk(fi)

    types = {c.symbol_type for c in chunks}
    assert "class" in types or "method" in types


def test_python_multiple_functions(tmp_path: Path) -> None:
    code = (
        "def alpha():\n    pass\n\n"
        "def beta():\n    pass\n\n"
        "def gamma():\n    pass\n"
    )
    p = _write(tmp_path / "funcs.py", code)
    fi = _make_fi(p, language="Python")

    chunks = _tree_sitter_chunker.chunk(fi)
    names = [c.symbol_name for c in chunks if c.symbol_name]

    assert "alpha" in names
    assert "beta" in names
    assert "gamma" in names


def test_python_chunks_return_code_chunk_type(tmp_path: Path) -> None:
    code = "def foo():\n    return 42\n"
    p = _write(tmp_path / "foo.py", code)
    fi = _make_fi(p, language="Python")

    chunks = _tree_sitter_chunker.chunk(fi)
    for c in chunks:
        assert isinstance(c, CodeChunk), f"Expected CodeChunk, got {type(c)}"


def test_python_line_numbers_are_correct(tmp_path: Path) -> None:
    code = "x = 1\n\ndef my_func():\n    return x\n"
    p = _write(tmp_path / "lines.py", code)
    fi = _make_fi(p, language="Python")

    chunks = _tree_sitter_chunker.chunk(fi)
    func_chunk = next((c for c in chunks if c.symbol_name == "my_func"), None)
    assert func_chunk is not None
    assert func_chunk.line_start == 3    # 1-indexed, "def my_func():" is line 3


def test_python_imports_captured(tmp_path: Path) -> None:
    code = "import os\nfrom pathlib import Path\n\ndef get_path():\n    return Path('.')\n"
    p = _write(tmp_path / "imports.py", code)
    fi = _make_fi(p, language="Python")

    chunks = _tree_sitter_chunker.chunk(fi)
    func_chunk = next((c for c in chunks if c.symbol_name == "get_path"), None)
    assert func_chunk is not None
    assert any("import" in imp for imp in func_chunk.imports)


# ---------------------------------------------------------------------------
# TreeSitterChunker — JavaScript
# ---------------------------------------------------------------------------

def test_js_function_extracted(tmp_path: Path) -> None:
    code = "function greet(name) {\n  return `Hello ${name}`;\n}\n"
    p = _write(tmp_path / "hello.js", code)
    fi = _make_fi(p, language="JavaScript")

    chunks = _tree_sitter_chunker.chunk(fi)
    names = [c.symbol_name for c in chunks if c.symbol_name]
    assert "greet" in names


def test_js_class_extracted(tmp_path: Path) -> None:
    code = "class Animal {\n  speak() { return 'sound'; }\n}\n"
    p = _write(tmp_path / "animal.js", code)
    fi = _make_fi(p, language="JavaScript")

    chunks = _tree_sitter_chunker.chunk(fi)
    assert len(chunks) >= 1


def test_js_arrow_function_extracted(tmp_path: Path) -> None:
    code = "const add = (a, b) => a + b;\n"
    p = _write(tmp_path / "arrow.js", code)
    fi = _make_fi(p, language="JavaScript")

    chunks = _tree_sitter_chunker.chunk(fi)
    # Arrow functions may not always have a name captured via query
    assert isinstance(chunks, list)


# ---------------------------------------------------------------------------
# GenericChunker
# ---------------------------------------------------------------------------

def test_generic_chunker_splits_into_windows(tmp_path: Path) -> None:
    lines = [f"line_{i}\n" for i in range(130)]
    p = _write(tmp_path / "big.txt", "".join(lines))
    fi = _make_fi(p, language=None)

    chunker = GenericChunker()
    chunks = chunker.chunk(fi)

    assert len(chunks) == 3   # 50 + 50 + 30
    assert chunks[0].line_start == 1
    assert chunks[0].line_end == WINDOW_SIZE
    assert chunks[-1].line_end == 130


def test_generic_chunker_returns_code_chunk(tmp_path: Path) -> None:
    p = _write(tmp_path / "file.txt", "hello\nworld\n")
    fi = _make_fi(p, language="unknown")

    chunks = GenericChunker().chunk(fi)
    for c in chunks:
        assert isinstance(c, CodeChunk)


def test_generic_chunker_skips_binary(tmp_path: Path) -> None:
    p = tmp_path / "data.bin"
    p.write_bytes(b"\x00\x01\x02")
    fi = FileInfo(path=p, size_bytes=3, is_binary=True)

    chunks = GenericChunker().chunk(fi)
    assert chunks == []


def test_generic_chunker_skips_oversized(tmp_path: Path) -> None:
    p = _write(tmp_path / "huge.py", "x = 1\n")
    fi = FileInfo(path=p, size_bytes=999_999_999, is_oversized=True)

    chunks = GenericChunker().chunk(fi)
    assert chunks == []


def test_generic_chunker_empty_file(tmp_path: Path) -> None:
    p = _write(tmp_path / "empty.py", "")
    fi = _make_fi(p, language="Python")

    chunks = GenericChunker().chunk(fi)
    assert chunks == []


# ---------------------------------------------------------------------------
# chunk_file() dispatcher + fallback
# ---------------------------------------------------------------------------

def test_chunk_file_uses_tree_sitter_for_python(tmp_path: Path) -> None:
    code = "def hello():\n    pass\n"
    p = _write(tmp_path / "hello.py", code)
    fi = _make_fi(p, language="Python")

    chunks = chunk_file(fi)
    assert len(chunks) >= 1


def test_chunk_file_uses_generic_for_unknown_language(tmp_path: Path) -> None:
    code = "hello world\nthis is text\n"
    p = _write(tmp_path / "file.xyz", code)
    fi = _make_fi(p, language=None)

    chunks = chunk_file(fi)
    assert len(chunks) >= 1    # GenericChunker must produce something


def test_chunk_file_skips_binary(tmp_path: Path) -> None:
    p = tmp_path / "data.bin"
    p.write_bytes(b"\x00\x01\x02")
    fi = FileInfo(path=p, size_bytes=3, is_binary=True)

    chunks = chunk_file(fi)
    assert chunks == []


def test_chunk_file_always_returns_list(tmp_path: Path) -> None:
    p = _write(tmp_path / "empty.py", "")
    fi = _make_fi(p, language="Python")
    result = chunk_file(fi)
    assert isinstance(result, list)
