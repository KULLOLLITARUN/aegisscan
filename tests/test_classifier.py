"""Tests for FileClassifier.

Covers (per plan §4 V0):
  - Language detection by extension
  - Language detection by filename (Dockerfile, Makefile)
  - Binary file detection (null-byte probe)
  - Generated file detection (lock files, minified JS, auto-gen headers)
  - Oversized file detection
  - Unreadable file (conservative binary fallback)
  - Line counting
  - FileInfo is always a typed Pydantic model — never a raw dict
"""
from __future__ import annotations

from pathlib import Path

import pytest

from scanner.ingestion.classifier import MAX_FILE_SIZE_BYTES, FileClassifier
from scanner.models.file_info import FileInfo


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(path: Path, content: str = "line1\nline2\nline3") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _write_bytes(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


# ---------------------------------------------------------------------------
# Return type contract
# ---------------------------------------------------------------------------

def test_always_returns_file_info(tmp_path: Path) -> None:
    """classify() must always return a FileInfo, never a raw dict."""
    _write(tmp_path / "main.py")
    fi = FileClassifier().classify(tmp_path / "main.py")
    assert isinstance(fi, FileInfo)


# ---------------------------------------------------------------------------
# Language detection — extension
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "filename, expected_lang",
    [
        ("app.py", "Python"),
        ("index.js", "JavaScript"),
        ("component.tsx", "TypeScript"),
        ("styles.css", "CSS"),
        ("schema.sql", "SQL"),
        ("config.yaml", "YAML"),
        ("config.yml", "YAML"),
        ("settings.toml", "TOML"),
        ("main.go", "Go"),
        ("lib.rs", "Rust"),
        ("Main.java", "Java"),
        ("main.c", "C"),
        ("main.cpp", "C++"),
        ("script.sh", "Shell"),
        ("module.rb", "Ruby"),
        ("index.php", "PHP"),
        ("README.md", "Markdown"),
        ("setup.tf", "Terraform"),
        ("query.graphql", "GraphQL"),
    ],
)
def test_language_by_extension(tmp_path: Path, filename: str, expected_lang: str) -> None:
    _write(tmp_path / filename)
    fi = FileClassifier().classify(tmp_path / filename)
    assert fi.language == expected_lang, f"Expected {expected_lang} for {filename}, got {fi.language}"


@pytest.mark.parametrize(
    "filename",
    ["Dockerfile", "Makefile"],
)
def test_language_by_exact_filename(tmp_path: Path, filename: str) -> None:
    _write(tmp_path / filename, "FROM python:3.12\n")
    fi = FileClassifier().classify(tmp_path / filename)
    assert fi.language is not None


def test_unknown_extension_gives_none_language(tmp_path: Path) -> None:
    _write(tmp_path / "file.xyz123")
    fi = FileClassifier().classify(tmp_path / "file.xyz123")
    assert fi.language is None


# ---------------------------------------------------------------------------
# Binary detection
# ---------------------------------------------------------------------------

def test_binary_file_detected(tmp_path: Path) -> None:
    """A file containing null bytes must be flagged is_binary=True."""
    _write_bytes(tmp_path / "image.bin", b"\x00\x01\x02\x03binary data")
    fi = FileClassifier().classify(tmp_path / "image.bin")
    assert fi.is_binary is True
    assert fi.line_count is None


def test_binary_file_no_line_count(tmp_path: Path) -> None:
    _write_bytes(tmp_path / "data.dat", b"PNG\x00header\x00more data")
    fi = FileClassifier().classify(tmp_path / "data.dat")
    assert fi.is_binary is True
    assert fi.line_count is None


def test_text_file_not_binary(tmp_path: Path) -> None:
    _write(tmp_path / "main.py", "print('hello')\n")
    fi = FileClassifier().classify(tmp_path / "main.py")
    assert fi.is_binary is False


def test_unicode_text_not_binary(tmp_path: Path) -> None:
    """UTF-8 text with non-ASCII characters must not be flagged as binary."""
    (tmp_path / "unicode.py").write_text(
        "# 日本語コメント\nprint('café')\n", encoding="utf-8"
    )
    fi = FileClassifier().classify(tmp_path / "unicode.py")
    assert fi.is_binary is False


# ---------------------------------------------------------------------------
# Generated file detection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "filename",
    [
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "Pipfile.lock",
        "poetry.lock",
        "Cargo.lock",
        "go.sum",
        "composer.lock",
    ],
)
def test_known_lock_files_are_generated(tmp_path: Path, filename: str) -> None:
    _write(tmp_path / filename, '{"lockfileVersion": 2}')
    fi = FileClassifier().classify(tmp_path / filename)
    assert fi.is_generated is True, f"{filename} should be detected as generated"


@pytest.mark.parametrize(
    "filename",
    ["bundle.min.js", "styles.min.css", "app.bundle.js"],
)
def test_minified_files_are_generated(tmp_path: Path, filename: str) -> None:
    _write(tmp_path / filename, "var a=1;var b=2;")
    fi = FileClassifier().classify(tmp_path / filename)
    assert fi.is_generated is True


@pytest.mark.parametrize(
    "header",
    [
        "// This file is auto-generated. Do not edit.\n",
        "# auto-generated by protoc -- DO NOT EDIT\n",
        "/* @generated */\n",
        "// Code generated by go generate; DO NOT EDIT.\n",
        "// Auto-generated. This code was generated by a tool.\n",
    ],
)
def test_auto_gen_header_detected(tmp_path: Path, header: str) -> None:
    _write(tmp_path / "generated.py", header + "x = 1\n")
    fi = FileClassifier().classify(tmp_path / "generated.py")
    assert fi.is_generated is True


def test_normal_file_not_generated(tmp_path: Path) -> None:
    _write(tmp_path / "main.py", "def main():\n    pass\n")
    fi = FileClassifier().classify(tmp_path / "main.py")
    assert fi.is_generated is False


# ---------------------------------------------------------------------------
# Oversized file detection
# ---------------------------------------------------------------------------

def test_oversized_file_flagged(tmp_path: Path) -> None:
    """A file above MAX_FILE_SIZE_BYTES must be is_oversized=True."""
    big = tmp_path / "big.py"
    big.write_bytes(b"x" * (MAX_FILE_SIZE_BYTES + 1))
    fi = FileClassifier().classify(big)
    assert fi.is_oversized is True
    assert fi.line_count is None  # not read


def test_just_under_limit_not_oversized(tmp_path: Path) -> None:
    edge = tmp_path / "edge.py"
    edge.write_bytes(b"x" * (MAX_FILE_SIZE_BYTES - 1))
    fi = FileClassifier().classify(edge)
    assert fi.is_oversized is False


def test_empty_file_not_oversized(tmp_path: Path) -> None:
    _write(tmp_path / "empty.py", "")
    fi = FileClassifier().classify(tmp_path / "empty.py")
    assert fi.is_oversized is False


# ---------------------------------------------------------------------------
# Line counting
# ---------------------------------------------------------------------------

def test_line_count_accuracy(tmp_path: Path) -> None:
    content = "line1\nline2\nline3\n"  # 3 lines
    _write(tmp_path / "three.py", content)
    fi = FileClassifier().classify(tmp_path / "three.py")
    assert fi.line_count == 3


def test_line_count_no_trailing_newline(tmp_path: Path) -> None:
    content = "line1\nline2"  # 2 lines, no trailing newline
    _write(tmp_path / "two.py", content)
    fi = FileClassifier().classify(tmp_path / "two.py")
    assert fi.line_count == 2


def test_single_line_file(tmp_path: Path) -> None:
    _write(tmp_path / "one.py", "print('hi')")
    fi = FileClassifier().classify(tmp_path / "one.py")
    assert fi.line_count == 1


def test_empty_file_line_count(tmp_path: Path) -> None:
    _write(tmp_path / "empty.py", "")
    fi = FileClassifier().classify(tmp_path / "empty.py")
    # Empty file: 0 or 1 are both defensible; assert it's not None
    assert fi.line_count is not None


# ---------------------------------------------------------------------------
# Size tracking
# ---------------------------------------------------------------------------

def test_size_bytes_matches_actual(tmp_path: Path) -> None:
    content = "hello"
    p = tmp_path / "hello.py"
    p.write_text(content, encoding="utf-8")
    fi = FileClassifier().classify(p)
    assert fi.size_bytes == p.stat().st_size


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------

def test_nonexistent_file_returns_file_info(tmp_path: Path) -> None:
    """classify() must not raise even for missing files."""
    missing = tmp_path / "does_not_exist.py"
    fi = FileClassifier().classify(missing)
    assert isinstance(fi, FileInfo)
    assert fi.is_binary is True  # conservative fallback


def test_file_info_is_frozen(tmp_path: Path) -> None:
    """FileInfo should be immutable (frozen Pydantic model)."""
    _write(tmp_path / "main.py")
    fi = FileClassifier().classify(tmp_path / "main.py")
    with pytest.raises(Exception):
        fi.language = "changed"  # type: ignore[misc]
