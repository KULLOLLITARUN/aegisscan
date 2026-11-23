# How AegisScan Works

.\.venv\Scripts\activate
>> aegisscan --server --port 8000


(.venv) PS D:\AI_Projects\AI-Driven_Workspace_Security_&_Optimization_Scanner> .\.venv\Scripts\activate
>> aegisscan


This document walks through what actually happens, module by module, when you run:

```bash
aegisscan <path>
```

The orchestration lives in [`main.py`](main.py) → `run()`. Everything else is implemented in [`scanner/`](scanner/), organized by pipeline stage.

---

## The pipeline, in order

```
crawl → classify → chunk → static analysis → LLM reasoning
      → deduplicate → correlate → baseline suppress → score → ScanResult
      → persist to history → CLI / HTML / SARIF / JSON report → CI gate
```

### 1. Crawl — `scanner/ingestion/crawler.py`

`WorkspaceCrawler` walks the target directory with `pathlib`, honoring `.gitignore` rules (including nested ones) so it never touches `node_modules/`, build artifacts, or anything you've already excluded. If `--changed-only` is passed, [`scanner/ingestion/git_diff.py`](scanner/ingestion/git_diff.py) intersects the discovered files with `git status` and `git diff HEAD` (modified/staged/untracked), so chunking, the LLM pass, the static tools and the reported findings all cover only what changed: Bandit, Semgrep, Gitleaks and the optimizer are handed just the changed files (in batches that fit the command-line length limit; Gitleaks, which takes one path per run, is run per file for up to 25 files and once on the tree beyond that). The results are the same as a full scan restricted to those files, only faster, and nothing is started when no file changed. Findings in unchanged files are still dropped as a safety net. Outside a git repository, or if git fails, the whole tree is scanned. Not covered: cross-file analysis (a change can introduce an issue that only shows up when an unchanged file is read with it), and Semgrep's fixed start-up cost, which `--changed-only` does not remove.

### 2. Classify — `scanner/ingestion/classifier.py`

Every discovered path becomes a `FileInfo` (a Pydantic model): detected language, line count, and three flags — `is_binary`, `is_generated`, `is_oversized` (>1MB). Files flagged this way are counted but skipped by every later stage — they're never chunked, scanned, or sent to an LLM.

### 3. Chunk — `scanner/chunking/dispatcher.py`

For every remaining file, `chunk_file()` picks a strategy:
- **Tree-sitter** ([`tree_sitter_chunker.py`](scanner/chunking/tree_sitter_chunker.py)) for Python/JavaScript/TypeScript — parses the AST and slices out functions, classes, and methods as individually addressable `CodeChunk`s (with line ranges and imports attached).
- **Generic line-based chunker** ([`generic_chunker.py`](scanner/chunking/generic_chunker.py)) for everything else, or as a fallback if Tree-sitter fails on a file — this is the "graceful degradation" rule in practice: a parse error never kills the scan.

### 4. Static analysis — `scanner/static_analysis/runner.py`

`run_all_tools()` runs Bandit, Semgrep, and Gitleaks concurrently against the target directory and normalizes every tool's native output into the shared `Finding` model (file, line range, evidence, severity, `rule_source="bandit"/"semgrep"/"gitleaks"`). This stage never touches the network and needs no API key — it's what `--static-only` limits you to.

### 5. LLM reasoning — `scanner/llm/`

This stage is skipped entirely with `--static-only`. Otherwise:

- **Trigger engine** ([`trigger.py`](scanner/llm/trigger.py)) decides *which* chunks are worth an LLM call: a chunk qualifies if a static tool already flagged something nearby, if it matches a risky pattern (e.g. `eval`, `pickle.loads`, raw SQL string building), or if `--deep` forces every chunk through.
- **Redactor** ([`redactor.py`](scanner/llm/redactor.py)) scrubs the chunk before it ever leaves the machine, per `--privacy standard|redact|strict`: `standard` strips secrets/API keys/passwords, `redact` also strips emails and IPs, `strict` additionally masks string literals. This runs unconditionally — no code reaches an external provider unredacted.
- **Provider manager** ([`providers/manager.py`](scanner/providers/manager.py)) sends the redacted chunk + prompt to **Groq (cloud)**, falling back to static-only results if it is unavailable, with token-bucket rate limiting and exponential backoff (`rate_limiter.py`). The LLM auditor (`auditor.py`) never talks to a provider SDK directly — everything goes through this manager, so swapping/adding providers doesn't touch the auditor.
- Findings below `SUPPRESSION_THRESHOLD` confidence are dropped before they're even reported.
- If `--generate-patches` is set, [`patcher.py`](scanner/llm/patcher.py) asks the LLM for a unified `git diff` fix for each high-confidence finding.

### 6. Deduplicate — `scanner/intelligence/deduplicator.py`

Findings that describe the same underlying issue (same location + same category) from different sources are collapsed into one, with a count of how many were merged (`findings_deduplicated`).

### 7. Correlate — `scanner/intelligence/correlator.py`

Findings are grouped only when **both** location *and* semantic category match — e.g. a Semgrep "SQL Injection" and an LLM note on the exact same line correlate; a Semgrep security finding and an unrelated LLM performance note on that line do not. Groups where multiple independent tools agree are marked `is_corroborated`, which boosts confidence in the report.

### 8. Baseline suppression — `scanner/intelligence/baseline.py`

If `--baseline <file>` is given, `BaselineManager` fingerprints each finding and drops anything already present in that file — this is how you accept known/existing issues and only get alerted on *new* ones. `--save-baseline <file>` writes the current run's fingerprints out for next time.

### 9. Scoring — `scanner/scoring/calculator.py`

`security_score()` and `optimization_score()` reduce the final finding list to two 0–100 heuristic scores (weighted by severity/confidence, not calibrated against a CVE dataset — the report says so explicitly).

### 10. Persist — `scanner/storage/history.py`

Every run is written to a per-target SQLite file (`.aegisscan_history.db`) via `ScanHistoryDB.record_scan()`. `aegisscan --history` reads it back and prints score deltas between runs; `aegisscan --server` serves the same data as a local web dashboard ([`scanner/server/app.py`](scanner/server/app.py)).

### 11. Report

The same `ScanResult` (a Pydantic model — file counts, scores, the full `findings` list, LLM telemetry) feeds four outputs: the Rich CLI summary (`_print_report` in `main.py`), a self-contained "Midnight Obsidian" dark-mode HTML report (`--html`, `reporting/html_report.py`), a SARIF v2.1.0 file for GitHub's Security tab (`--sarif`, `reporting/sarif_report.py`), or raw `--json`.

### 12. CI gate — `scanner/ci/ci_gate.py`

`--fail-on security:high` (or `critical`, etc.) checks the final findings against a threshold and exits with code `2` if it's breached — this is the hook a CI pipeline uses to actually block a merge.

---

## The core contract: everything is a `Finding`

No matter whether it came from Bandit, Semgrep, Gitleaks, or the LLM, every result is normalized into the same Pydantic model (`scanner/models/finding.py`):

```
id, file_path, line_start/end, issue_type, category,
severity, confidence, evidence, explanation,
suggested_fix, fix_patch, rule_source, provider, model
```

Two axes matter and are kept independent: **severity** (how bad *if true*) and **confidence** (how sure we are it's true). A `critical` finding at `confidence: 0.6` means "investigate this," not "ignore it" and not "page someone."

## Design rules that shape all of the above

1. Static tools detect; the LLM only reasons/explains/correlates/patches on top of what they find (or on deep-scan chunks) — it's never the sole detector.
2. The auditor talks to `ProviderManager`, never to a provider SDK directly.
3. Every module boundary passes typed Pydantic models, never raw dicts.
4. Any code sent to an external LLM passes through redaction first — no exceptions.
5. If Tree-sitter, a static tool, or the LLM provider is unavailable, the scan still completes and produces a valid report.

See [`Plans/AEGISSCAN_PLAN.md`](Plans/AEGISSCAN_PLAN.md) for the full versioned roadmap this was built against.
