"""
FileInfo — represents a single file discovered by the workspace crawler.

This is the output contract of the ingestion layer. Every downstream module
(chunking, static analysis, LLM auditor) receives FileInfo objects — never
raw dicts or bare paths.
"""
from pathlib import Path
from typing import Optional

from pydantic import BaseModel


class FileInfo(BaseModel):
    """Metadata about a single file discovered during workspace crawl."""

    path: Path
    language: Optional[str] = None      # detected language, None if unknown
    size_bytes: int = 0
    line_count: Optional[int] = None    # None for binary / oversized files
    is_binary: bool = False
    is_generated: bool = False          # lock files, minified JS, auto-gen headers
    is_oversized: bool = False          # above MAX_FILE_SIZE_BYTES threshold

    model_config = {"frozen": True}
