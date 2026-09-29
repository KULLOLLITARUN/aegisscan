"""
GenericChunker — fallback chunker for unsupported languages or Tree-sitter failures.

Splits a file into fixed 50-line windows so downstream static tools always have
something to work with even when Tree-sitter is unavailable or the language is
not yet supported.

Design rule (plan §2 rule 6): graceful degradation — the scanner must still
produce a valid result when Tree-sitter fails.
"""
from __future__ import annotations

import logging

from scanner.chunking.base import BaseChunker
from scanner.models.chunk import CodeChunk
from scanner.models.file_info import FileInfo

log = logging.getLogger(__name__)

WINDOW_SIZE = 50  # lines per generic chunk


class GenericChunker(BaseChunker):
    """
    Splits a text file into fixed 50-line windows.

    Used as:
    - Fallback when Tree-sitter fails to parse a file
    - Default for languages without a Tree-sitter grammar in V1
    """

    def chunk(self, file_info: FileInfo) -> list[CodeChunk]:
        if file_info.is_binary or file_info.is_oversized:
            return []

        try:
            text = file_info.path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            log.warning("GenericChunker: cannot read %s: %s", file_info.path, exc)
            return []

        lines = text.splitlines(keepends=True)
        if not lines:
            return []

        language = file_info.language or "unknown"
        chunks: list[CodeChunk] = []

        for start_idx in range(0, len(lines), WINDOW_SIZE):
            end_idx = min(start_idx + WINDOW_SIZE, len(lines))
            window_code = "".join(lines[start_idx:end_idx])
            chunks.append(
                CodeChunk(
                    file_path=file_info.path,
                    language=language,
                    symbol_name=None,
                    symbol_type="module",       # generic windows are module-level
                    line_start=start_idx + 1,   # 1-indexed
                    line_end=end_idx,
                    code=window_code,
                    imports=[],
                )
            )

        return chunks
