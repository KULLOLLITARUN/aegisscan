# AegisScan — AI-Driven Workspace Security & Optimization Scanner

> **AegisScan** is a hybrid multi-layered security pipeline combining deterministic static analysis (Bandit, Semgrep, GitLeaks) with structured LLM AI reasoning (Groq, Ollama) to analyze codebases for security vulnerabilities, secrets, and performance anti-patterns.

---

## 🌟 Key Architecture & Pipeline Features

AegisScan operates through a 10-stage hybrid analysis pipeline:

1. **Ingestion & Classification**: Fast workspace crawling with `.gitignore` compliance, file classifier for binary/generated/oversized files, and per-language Tree-sitter AST chunking.
2. **Deterministic Static Analysis**: Concurrent multi-tool execution using `Bandit`, `Semgrep`, and `GitLeaks`.
3. **AI Triggering & Secret Redaction**: Selective triggering rules (risky patterns, static findings, or `--deep` pass) with regex-based multi-mode secret scrubbing (`--privacy standard|redact|strict`).
4. **Resilient LLM Provider Chain**: Multi-provider fallback chain (`Groq` cloud LLM → `Ollama` local LLM → Graceful Static Fallback) with token-bucket rate limiting and exponential backoff.
5. **AI Fix Patch Generator**: Automatic prompt engineering for high-confidence security findings to output production-ready unified `git diff` patches (`--generate-patches`).
6. **Intelligence Layer**: Location & category deduplication, multi-tool correlation confidence boosting, and `.security-baseline.json` suppression.
7. **Scoring & Reporting**: "Midnight Obsidian" dark-mode HTML reports with SVG score gauges, inline AI diff patches, JSON export, and rich CLI terminal summary.
8. **CI/CD Integration**: Incremental Git diff scanning (`--changed-only`) and build gate enforcement (`--fail-on security:high`).
9. **SQLite Scan History Persistence**: Automatic recording of scan results, security score trends, and score delta tracking (`aegisscan --history`).
10. **Interactive Web Server**: Built-in zero-dependency local dashboard web server (`aegisscan --server --port 8000`).

---

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/user/aegisscan.git
cd aegisscan

# Create virtual environment and install AegisScan as a global executable CLI
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e .
```

### Environment Setup

Copy `.env.example` to `.env` and add your Groq API key:

```env
GROQ_API_KEY=gsk_your_groq_api_key_here
```

*(If no API key is provided, AegisScan automatically falls back to local Ollama or static-only mode).*

---

## 🛠️ CLI Usage & Flags

```bash
# Global CLI command
aegisscan .

# Run LLM pass on ALL eligible code chunks
aegisscan . --deep

# Generate AI Unified Git Diff Fix Patches for findings
aegisscan . --generate-patches

# Launch Interactive Web Dashboard Server on port 8000
aegisscan --server --port 8000

# View SQLite Scan History & Score Deltas
aegisscan --history

# Static analysis only (offline mode, no API dependencies)
aegisscan . --static-only

# Incremental scan (only git modified/staged/untracked files)
aegisscan . --changed-only

# CI Gate (fail pipeline with exit code 2 if High/Critical security findings exist)
aegisscan . --fail-on security:high

# Secret redaction privacy level before sending code to LLM
aegisscan . --privacy standard   # Scrub secrets, API keys, passwords
aegisscan . --privacy redact     # standard + scrub emails & IP addresses
aegisscan . --privacy strict     # redact + mask all string literals

# Generate Midnight Obsidian HTML Report with inline AI patch diffs
aegisscan . --html report.html

# Output raw JSON ScanResult
aegisscan . --json

# Run Precision/Recall Calibration Benchmark Suite
aegisscan --benchmark
```

---

## 🧪 Benchmark & Quality Calibration

AegisScan includes a benchmark evaluation runner against fixed test suites:
- `examples/vulnerable_python/` — 3 files with deliberate SQL injection, hardcoded secrets, and injection patterns
- `examples/clean_project/` — 2 files using parameterized queries, env-var secrets, no known risks

```bash
aegisscan --benchmark --static-only
```

```
============================================================
 AEGISSCAN BENCHMARK & CALIBRATION REPORT (V7)
============================================================
 Vulnerable Python Findings : 12
 Clean Project Findings     : 0 (False Positives)
 True Positives (TP)        : 12
 False Positives (FP)       : 0
------------------------------------------------------------
 Precision                  : 100.00%
 Recall                     : 100.00%
 F1 Score                   : 100.00%
 False Positive Rate (FPR)  : 0.00%
 Total Evaluation Time      : 1.05s
============================================================
```

---

## 🧪 Automated Testing

AegisScan is protected by a 183-test automated unit suite covering crawler logic, tree-sitter chunking, static analysis runners, LLM failover, scoring engines, CI build gates, SQLite persistence, and web server endpoints.

```bash
pytest tests/ -v
# Output: 183 passed, 2 skipped in 24s
```

---

## 🛡️ License

MIT License — free for open-source and commercial use.
