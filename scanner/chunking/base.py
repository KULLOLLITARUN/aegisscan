"""
BaseChunker — abstract contract for all chunker implementations.

All chunkers receive a FileInfo and return a list[CodeChunk].
No raw dicts cross this boundary (plan §2 rule 3).
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from scanner.models.chunk import CodeChunk
from scanner.models.file_info import FileInfo


class BaseChunker(ABC):
    """Abstract base for all chunker implementations."""

    @abstractmethod
    def chunk(self, file_info: FileInfo) -> list[CodeChunk]:
        """
        Extract semantic units from *file_info* and return them as CodeChunks.

        Must never raise — return an empty list on any unrecoverable error.
        """
        ...
