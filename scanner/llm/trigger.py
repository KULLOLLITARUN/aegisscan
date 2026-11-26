"""
TriggerEngine — decides which CodeChunks the LLM auditor should analyze.

Design rule (plan §2 rule 1): The LLM is NEVER the primary detector.
It only runs on chunks that either have a static finding OR contain a pattern
that warrants closer scrutiny. This prevents burning API quota on clean code.

Trigger modes (plan §4 V2):
  1. Chunk has ≥1 static finding on it           → always trigger
  2. Chunk contains a risky code pattern         → trigger for deeper look
  3. --deep mode                                 → trigger on all eligible chunks
"""
from __future__ import annotations

import re

from scanner.models.chunk import CodeChunk
from scanner.models.finding import Finding

# ---------------------------------------------------------------------------
# Risky patterns — trigger LLM even without a static finding
# ---------------------------------------------------------------------------

_RISKY_PATTERNS: list[re.Pattern] = [
    re.compile(r'\beval\s*\(', re.IGNORECASE),
    re.compile(r'\bexec\s*\(', re.IGNORECASE),
    re.compile(r'\b__import__\s*\('),
    re.compile(r'\bpickle\.(loads?|dumps?)\b'),
    re.compile(r'\bmarsh(al)?\.(loads?|dumps?)\b'),
    re.compile(r'\bsubprocess\.\w+\s*\(.*shell\s*=\s*True'),
    re.compile(r'\bos\.(system|popen|exec[lv]p?)\s*\('),
    re.compile(r'\bhashlib\.(md5|sha1)\s*\('),
    re.compile(r'SELECT\s+.*\+\s*', re.IGNORECASE),          # SQL concatenation
    re.compile(r'(password|secret|key|token)\s*=\s*["\'].{6,}["\']', re.IGNORECASE),
    re.compile(r'\bxml\.(etree|sax|dom)'),                    # XML parsing (XXE risk)
    re.compile(r'\byaml\.load\s*\((?!.*Loader)'),             # unsafe yaml.load
    re.compile(r'\bdeserializ'),
    # --- Java ---
    re.compile(r'\bRuntime\.getRuntime\(\)\.exec\b'),
    re.compile(r'\bnew\s+ProcessBuilder\b'),
    re.compile(r'\b(ObjectInputStream|XMLDecoder)\b'),                       # unsafe deserialization
    re.compile(r'\b(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\b'),   # XXE
    re.compile(r'\bMessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"', re.IGNORECASE),
    # --- JavaScript / TypeScript ---
    re.compile(r'\bchild_process\b'),
    re.compile(r'\bnew\s+Function\s*\('),
    re.compile(r'\.(innerHTML|outerHTML)\s*=|\bdocument\.write\s*\(|\bdangerouslySetInnerHTML\b'),
    re.compile(r'\bcreateHash\(\s*["\'](md5|sha1)["\']', re.IGNORECASE),
    # --- Go ---
    re.compile(r'\bexec\.Command(Context)?\s*\('),
    re.compile(r'\b(md5|sha1)\.(New|Sum)\b'),
    re.compile(r'\bInsecureSkipVerify\s*:\s*true'),
    # --- PHP ---
    re.compile(r'\bunserialize\s*\('),
    re.compile(r'\b(shell_exec|passthru|proc_open|popen|system)\s*\('),
    re.compile(r'\b(include|require)(_once)?\s*\(?\s*\$'),                   # file inclusion
    # --- C# ---
    re.compile(r'\bProcess\.Start\s*\('),
    re.compile(r'\bBinaryFormatter\b'),
    re.compile(r'\b(MD5|SHA1)(CryptoServiceProvider)?\.Create\s*\(|\bnew\s+(MD5|SHA1)CryptoServiceProvider\b'),
    re.compile(r'\bnew\s+XmlDocument\b|\bXmlTextReader\b'),
]

# Maximum chunk size to send to LLM (characters) — very large chunks are split
# by the generic chunker into 50-line windows so this rarely triggers
MAX_CHUNK_CHARS = 8_000


def _has_static_finding_on_chunk(chunk: CodeChunk, findings: list[Finding]) -> bool:
    """True if any finding's file + line range overlaps with this chunk."""
    for f in findings:
        if f.file_path != chunk.file_path:
            continue
        # Overlap: finding starts before chunk ends AND finding ends after chunk starts
        if f.line_start <= chunk.line_end and f.line_end >= chunk.line_start:
            return True
    return False


def _has_risky_pattern(code: str) -> bool:
    """True if the chunk's code contains any known risky pattern."""
    return any(p.search(code) for p in _RISKY_PATTERNS)


class TriggerEngine:
    """
    Decides whether a CodeChunk should be sent to the LLM auditor.

    Usage::

        engine = TriggerEngine()
        for chunk in chunks:
            if engine.should_analyze(chunk, static_findings, deep=args.deep):
                findings = auditor.analyze(chunk, static_findings)
    """

    def should_analyze(
        self,
        chunk: CodeChunk,
        static_findings: list[Finding],
        deep: bool = False,
    ) -> bool:
        """
        Return True if the LLM should analyze this chunk.

        Args:
            chunk          : the CodeChunk candidate
            static_findings: all static findings from V1 (for the entire target)
            deep           : if True, analyze all eligible chunks regardless of triggers
        """
        # Never analyze binary / oversized / empty chunks
        if not chunk.code.strip():
            return False
        if len(chunk.code) > MAX_CHUNK_CHARS:
            return False    # too large; generic chunker should have split it

        if deep:
            return True

        # Trigger 1: chunk has at least one static finding on it
        if _has_static_finding_on_chunk(chunk, static_findings):
            return True

        # Trigger 2: chunk contains a risky code pattern
        if _has_risky_pattern(chunk.code):
            return True

        return False

    def get_chunk_findings(
        self,
        chunk: CodeChunk,
        all_findings: list[Finding],
    ) -> list[Finding]:
        """Return only the static findings that fall within this chunk."""
        return [
            f for f in all_findings
            if f.file_path == chunk.file_path
            and f.line_start <= chunk.line_end
            and f.line_end >= chunk.line_start
        ]
