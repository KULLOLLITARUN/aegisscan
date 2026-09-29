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

## 🖥️ Web Dashboard

The React dashboard's build output (`scanner/server/dist`) is **not committed**. Build it once, then start the server:

```bash
cd ui
npm ci
npm run build          # writes scanner/server/dist (inside the Python package, so wheels include it)
cd ..
aegisscan --server --port 8000
```

Without the build the server still starts and serves a basic fallback page, and prints a reminder. Requires Node 22+ (Vite 8). For frontend work run `npm run dev` (port 5173, proxies `/api` to `127.0.0.1:8000`). CI lints and builds the UI on every push and uploads it as the `aegisscan-ui-dist` artifact.

> **Windows:** `npm run ...` fails if the project path contains `&` (for example `Security_&_Optimization`) because `cmd.exe` splits on it. Use a path without `&`, or call the tools directly: `node node_modules/vite/bin/vite.js build`.

---

## 🧪 Benchmark & Quality Calibration

`aegisscan --benchmark` scores the scanner against a ground-truth manifest, `examples/benchmark_labels.json`: 31 files (15 clean), 88 labelled issues, written by reading the code rather than from tool output. It includes a CVE-style corpus (`examples/benchmark_corpus/`: SQL injection, command injection, deserialization, weak crypto, TLS misuse, hardcoded secrets, plus safe look-alikes) and the performance fixtures.

```bash
aegisscan --benchmark --static-only                     # print the report
aegisscan --benchmark --benchmark-json metrics.json     # also write machine-readable metrics
```

It reports precision, recall, false-positive rate (share of clean files flagged), per-source precision, per-category recall, **confidence calibration** (reliability bins, ECE, Brier score) and, for LLM runs, JSON validity rate and latency per request. Recall is counted over the labels that an *active* tool is expected to catch, and separately over all labels.

Measured with Bandit + built-in secret scanner + optimizer (Semgrep off, which is what the test suite gates on):

| Metric | Value |
|---|---|
| Precision | 85.7% (72 TP / 12 FP) |
| Recall, labels in scope | 100% (66 labels) |
| Recall, all labels | 75% (the other 22 need Semgrep or an LLM) |
| Clean files flagged | 3 of 15 |
| Calibration | ECE 0.138, Brier 0.106 |

Read these as a small-sample baseline, not a quality claim: the corpus is self-authored, and the false positives are mostly Bandit notes on safe code (`import subprocess`, placeholder-built `IN (?,?)` SQL, allow-listed `ORDER BY`). Semgrep and LLM numbers depend on network and API access; in the last full run Semgrep was installed but contributed no findings, so the JavaScript labels showed as missed (in-scope recall 81%). No LLM run has been recorded yet.

---

## 🧪 Automated Testing

AegisScan is protected by a 382-test automated suite (4 opt-in live-provider tests are skipped without credentials) covering crawler logic, tree-sitter chunking, static analysis runners, LLM failover, scoring engines, CI build gates, SQLite persistence, and web server endpoints.

```bash
pytest tests/ -v
# Output: 382 passed, 4 skipped in ~90-120s
```

---

## 🛡️ License

MIT License — free for open-source and commercial use.

## Configuration

| Setting | Where | Purpose |
|---|---|---|
| `GROQ_API_KEY`, `OPENAI_API_KEY` | `.env` / environment | LLM providers (failover order: Groq → OpenAI → Ollama) |
| `OPENAI_BASE_URL`, `AEGISSCAN_OPENAI_MODEL` | environment | Point the OpenAI provider at a compatible endpoint / pick a model |
| `AEGISSCAN_GROQ_MODELS` | environment | Comma-separated Groq model ids (first is the default). Retired/unknown models are skipped automatically |
| `AEGISSCAN_LLM_WORKERS`, `AEGISSCAN_LLM_RPM` | environment | Parallel LLM calls (default 4) and the global requests-per-minute cap (default 10) |
| `AEGISSCAN_ALLOWED_ROOTS` | environment | Extra directories the web server may scan (`;` on Windows, `:` elsewhere). Default: project root only |
| `exclude_dirs` | `.aegisscan.toml` in the scan target | Directory names skipped by Bandit and the optimizer (tests/ and examples/ are scanned by default) |

Static tools: Bandit and the built-in optimizer ship with the package; install Semgrep with `pip install ".[static]"` and Gitleaks from its [releases page](https://github.com/gitleaks/gitleaks/releases). Missing tools are skipped, never fatal.

The web server (`--server`) binds to `127.0.0.1`, sends no CORS headers and rejects non-local `Host`/`Origin` headers.

Tree-sitter chunking covers Python, JavaScript, TypeScript, Go, Java, PHP and C#; other languages (including SQL) use the generic chunker.
