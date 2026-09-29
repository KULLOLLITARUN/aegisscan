"""
SqlChunker: statement-aware chunking for ``.sql`` files.

No maintained tree-sitter SQL grammar is trusted here, so this is a small
hand-written splitter that respects the constructs that break naive ``;`` splitting:

  * single-quoted strings (``''`` escapes; backslash escapes for ``E'..'`` and MySQL-style files)
  * double-quoted / backtick identifiers
  * ``-- line`` and nested ``/* block */`` comments
  * PostgreSQL dollar quoting (``$$ ... $$``, ``$fn$ ... $fn$``)
  * MySQL ``DELIMITER`` directives and T-SQL ``GO`` batch separators
  * ``BEGIN ... END`` / ``CASE ... END`` bodies of procedures, functions and triggers

Consecutive small statements are packed into chunks of at most ``MAX_CHUNK_LINES``
lines; routines are always their own chunk, and a statement longer than the limit
is never cut. Chunks are contiguous and lossless: the union of chunk text is the
file minus separators (``DELIMITER`` / ``GO`` lines).

Never raises: on any failure returns [] and the dispatcher falls back to GenericChunker.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from scanner.chunking.base import BaseChunker
from scanner.models.chunk import CodeChunk
from scanner.models.file_info import FileInfo

log = logging.getLogger(__name__)

MAX_CHUNK_LINES = 50

_DOLLAR_TAG = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$")
_DELIMITER_LINE = re.compile(r"[ \t]*DELIMITER[ \t]+(\S+)[ \t]*(?:\r?\n|$)", re.IGNORECASE)
_GO_LINE = re.compile(r"[ \t]*GO(?:[ \t]+\d+)?[ \t]*(?:--[^\r\n]*)?(?:\r?\n|$)", re.IGNORECASE)
_WORD = re.compile(r"[A-Za-z_]+")
_MYSQL_HINT = re.compile(r"`|\bDELIMITER\b|\bENGINE\s*=", re.IGNORECASE)

# BEGIN followed by these is a transaction statement, not a block opener.
_BEGIN_NOT_BLOCK = {"TRAN", "TRANSACTION", "WORK", "DEFERRED", "IMMEDIATE", "EXCLUSIVE", "ISOLATION", "READ"}
# END followed by these closes IF/LOOP/WHILE/REPEAT/FOR, none of which we count as openers.
_END_NOT_BLOCK = {"IF", "LOOP", "WHILE", "REPEAT", "FOR"}

_ROUTINE = re.compile(
    r"^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:DEFINER\s*=\s*\S+\s+)?"
    r"(?:TEMP(?:ORARY)?\s+|UNIQUE\s+|MATERIALIZED\s+)?"
    r"(?P<kind>TABLE|VIEW|INDEX|FUNCTION|PROCEDURE|TRIGGER|EVENT|PACKAGE|TYPE|SEQUENCE|SCHEMA|DATABASE)"
    r"(?:\s+IF\s+NOT\s+EXISTS)?\s+(?P<name>[\w.\"`\[\]$]+)",
    re.IGNORECASE,
)
_ROUTINE_KINDS = {"FUNCTION", "PROCEDURE", "TRIGGER", "EVENT", "PACKAGE"}
_VERB_OBJECT = re.compile(
    r"^\s*(?P<verb>INSERT\s+INTO|UPDATE|DELETE\s+FROM|SELECT|ALTER\s+\w+|DROP\s+\w+|GRANT|REVOKE|TRUNCATE(?:\s+TABLE)?|WITH|MERGE\s+INTO)"
    r"(?:\s+(?P<name>[\w.\"`\[\]]+))?",
    re.IGNORECASE,
)
_LEADING_COMMENTS = re.compile(r"\A(?:\s+|--[^\n]*\n?|/\*.*?\*/)*", re.DOTALL)


@dataclass(frozen=True)
class _Stmt:
    start: int   # offset of first non-blank char
    end: int     # offset one past last non-blank char
    name: str
    routine: bool


def _describe(text: str) -> tuple[str, bool]:
    """(short name, is_routine) for a statement, ignoring leading comments."""
    body = text[_LEADING_COMMENTS.match(text).end():]
    m = _ROUTINE.match(body)
    if m:
        kind = m.group("kind").upper()
        return f"CREATE {kind} {m.group('name')}", kind in _ROUTINE_KINDS
    m = _VERB_OBJECT.match(body)
    if m:
        verb = re.sub(r"\s+", " ", m.group("verb").upper())
        name = m.group("name")
        return (f"{verb} {name}" if name and verb not in ("SELECT", "WITH") else verb), False
    first = body.split(None, 1)[0].upper() if body.strip() else "SQL"
    return first[:30], False


def split_statements(text: str) -> list[_Stmt]:
    """Split *text* into statements (offsets into *text*); pure, exposed for testing."""
    mysql_like = bool(_MYSQL_HINT.search(text))
    n = len(text)
    i = 0
    delimiter = ";"
    stmt_start = 0          # offset where the current (possibly still blank) statement began
    depth = 0               # BEGIN/CASE nesting
    out: list[_Stmt] = []

    def flush(upto: int) -> None:
        nonlocal stmt_start, depth
        raw = text[stmt_start:upto]
        if raw.strip():
            lead = len(raw) - len(raw.lstrip())
            body = raw.strip()
            # a chunk that is only comments still carries text worth keeping
            name, routine = _describe(body)
            out.append(_Stmt(stmt_start + lead, stmt_start + lead + len(body), name, routine))
        stmt_start = upto
        depth = 0

    while i < n:
        ch = text[i]
        at_line_start = i == 0 or text[i - 1] == "\n"

        if at_line_start:
            m = _DELIMITER_LINE.match(text, i)
            if m and not text[stmt_start:i].strip():
                delimiter = m.group(1)
                i = stmt_start = m.end()
                continue
            m = _GO_LINE.match(text, i)
            if m and depth == 0:
                flush(i)
                i = stmt_start = m.end()
                continue

        # comments
        if text.startswith("--", i):
            j = text.find("\n", i)
            i = n if j == -1 else j + 1
            continue
        if text.startswith("/*", i):
            level, i = 1, i + 2
            while i < n and level:
                if text.startswith("/*", i):
                    level, i = level + 1, i + 2
                elif text.startswith("*/", i):
                    level, i = level - 1, i + 2
                else:
                    i += 1
            continue

        # quoted strings / identifiers
        if ch in ("'", '"', "`"):
            backslash = ch != "`" and (mysql_like or (i > 0 and text[i - 1] in "eE" and ch == "'"))
            i += 1
            while i < n:
                c = text[i]
                if backslash and c == "\\":
                    i += 2
                    continue
                if c == ch:
                    if i + 1 < n and text[i + 1] == ch:   # doubled quote escape
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            continue
        # dollar quoting
        if ch == "$":
            m = _DOLLAR_TAG.match(text, i)
            if m:
                token = m.group(0)
                j = text.find(token, m.end())
                i = n if j == -1 else j + len(token)
                continue

        # statement terminator
        if text.startswith(delimiter, i) and depth == 0:
            end = i + len(delimiter)
            flush(end if delimiter == ";" else i)   # keep ';' in the text, drop custom delimiters
            i = stmt_start = end
            continue

        # block depth for routine bodies
        if ch.isalpha() or ch == "_":
            m = _WORD.match(text, i)
            word = m.group(0).upper()
            end = m.end()
            if word == "CASE":
                depth += 1
            elif word == "BEGIN":
                nxt = _WORD.match(text, _skip_ws(text, end))
                if not (nxt and nxt.group(0).upper() in _BEGIN_NOT_BLOCK) and text[_skip_ws(text, end):][:1] != ";":
                    depth += 1
            elif word == "END" and depth > 0:
                nxt = _WORD.match(text, _skip_ws(text, end))
                if not (nxt and nxt.group(0).upper() in _END_NOT_BLOCK):
                    depth -= 1
            i = end
            continue
        i += 1

    flush(n)
    return out


def _skip_ws(text: str, i: int) -> int:
    while i < len(text) and text[i] in " \t\r\n":
        i += 1
    return i


class SqlChunker(BaseChunker):
    """Statement-aware chunker for SQL files (see module docstring)."""

    def chunk(self, file_info: FileInfo) -> list[CodeChunk]:
        if file_info.is_binary or file_info.is_oversized:
            return []
        try:
            text = file_info.path.read_text(encoding="utf-8", errors="replace")
            stmts = split_statements(text)
        except Exception as exc:  # never raise (BaseChunker contract)
            log.warning("SqlChunker failed on %s: %s", file_info.path, exc)
            return []
        if not stmts:
            return []

        def line_of(offset: int) -> int:
            return text.count("\n", 0, offset) + 1

        chunks: list[CodeChunk] = []
        group: list[_Stmt] = []

        def emit() -> None:
            if not group:
                return
            first, last = group[0], group[-1]
            if len(group) == 1:
                name, symbol_type = first.name, "function" if first.routine else "module"
            else:
                name, symbol_type = f"{first.name} (+{len(group) - 1} statements)", "module"
            chunks.append(CodeChunk(
                file_path=file_info.path,
                language=file_info.language or "SQL",
                symbol_name=name,
                symbol_type=symbol_type,
                line_start=line_of(first.start),
                line_end=line_of(last.end - 1),
                code=text[first.start:last.end],
                imports=[],
            ))
            group.clear()

        for stmt in stmts:
            if stmt.routine:
                emit()
                group.append(stmt)
                emit()
                continue
            span = line_of(stmt.end - 1) - (line_of(group[0].start) if group else line_of(stmt.start)) + 1
            if group and span > MAX_CHUNK_LINES:
                emit()
            group.append(stmt)
        emit()
        return chunks
