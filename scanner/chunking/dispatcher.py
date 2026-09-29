"""
Chunker dispatcher — routes each FileInfo to the right chunker.

Language-string contract (CRITICAL — plan §2 rule 3 + user feedback):
  The language strings here MUST exactly match what V0's FileClassifier sets
  on FileInfo.language via _EXT_TO_LANGUAGE. A silent mismatch causes every
  file to fall through to GenericChunker with no error.

  V0 classifier values that Tree-sitter supports in V1:
    "Python", "JavaScript", "TypeScript"

  All other language strings (or None) route to GenericChunker.
"""
from __future__ import annotations

import logging

from scanner.chunking.base import BaseChunker
from scanner.chunking.generic_chunker import GenericChunker
from scanner.chunking.tree_sitter_chunker import _TS_GRAMMAR_MAP, TreeSitterChunker
from scanner.models.file_info import FileInfo

log = logging.getLogger(__name__)

# Singleton instances — chunkers are stateless so one instance per type is fine
_tree_sitter_chunker = TreeSitterChunker()
_generic_chunker = GenericChunker()


def get_chunker(file_info: FileInfo) -> BaseChunker:
    """
    Return the appropriate chunker for *file_info*.

    - TreeSitterChunker for Python, JavaScript, TypeScript
    - GenericChunker for everything else (fallback)

    If TreeSitterChunker fails at runtime for a supported language it returns
    [] and the caller falls back to GenericChunker (see chunk_file()).
    """
    if file_info.language in _TS_GRAMMAR_MAP:
        return _tree_sitter_chunker
    return _generic_chunker


def chunk_file(file_info: FileInfo) -> list:
    """
    Chunk a single file, falling back to GenericChunker if Tree-sitter returns
    nothing (grammar load failure, parse error, empty file, etc.).

    Always returns list[CodeChunk].
    """

    if file_info.is_binary or file_info.is_oversized or file_info.is_generated:
        return []

    chunker = get_chunker(file_info)
    chunks = chunker.chunk(file_info)

    # If Tree-sitter returned nothing for a supported language → fall back
    if not chunks and chunker is _tree_sitter_chunker:
        log.debug(
            "Tree-sitter returned no chunks for %s (%s) — using GenericChunker",
            file_info.path.name,
            file_info.language,
        )
        chunks = _generic_chunker.chunk(file_info)

    return chunks
