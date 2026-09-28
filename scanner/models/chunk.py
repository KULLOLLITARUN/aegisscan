"""
CodeChunk — a semantic unit of code extracted from a source file.

V0 note: this file defines the *contract* only.
Actual chunking logic (Tree-sitter per-language chunkers) is implemented in V1.
The model exists here so that all module boundaries are typed correctly from
the start — no raw dicts ever cross a module boundary (plan §2 rule 3).
"""
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


class CodeChunk(BaseModel):
    """
    A semantic unit of code: a function, class, method, or top-level module block.

    Produced by the Tree-sitter chunker (V1+). In V0 no instances are created;
    the model is present purely to establish the typed contract.
    """

    file_path: Path
    language: str

    # Symbol extracted by Tree-sitter (None for fallback / generic chunks)
    symbol_name: Optional[str] = None   # e.g. "parse_user_input"
    symbol_type: Optional[str] = None   # "function" | "class" | "method" | "module"

    line_start: int
    line_end: int
    code: str                                           # raw source of the chunk
    imports: list[str] = Field(default_factory=list)   # imports visible in scope

    model_config = {"frozen": True}
