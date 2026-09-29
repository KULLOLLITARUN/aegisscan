# AegisScan — Remaining Issues & Testing Guide

_State as of 2026-09-29. Branch: `fix/server-hardening` (4 commits on top of the `main` baseline, not merged)._
_Test status: 215 passed, 4 skipped, coverage 82% (gate: 75%)._

---

## 1. What has been fixed (for context)

| Area | Change |
|---|---|
| Web server | Binds `127.0.0.1`, no CORS wildcard, foreign `Host`/`Origin` → 403, scan paths limited to project root + `AEGISSCAN_ALLOWED_ROOTS`, fake progress loop removed |
| Optimizer | New AST checker (`scanner/static_analysis/optimization_runner.py`): N+1 DB/network calls in loops, `+=` string building, nested loops over same collection, `re.<fn>(literal)` in loops. Python only |
| Providers | OpenAI provider added (Groq → OpenAI → Ollama); each provider uses its own default model on failover |
| Groq | Retired default models replaced (`openai/gpt-oss-20b`, `openai/gpt-oss-120b`, `qwen/qwen3.8-27b`); 404/unknown-model now advances to next model; `AEGISSCAN_GROQ_MODELS` override |
| Concurrency | Auditor uses a thread pool (`AEGISSCAN_LLM_WORKERS`, default 4); rate limiter + manager counters thread-safe |
| Redaction | Fixed AWS secret rule; added private keys, GitHub/Slack tokens, URL credentials |
| Prompt injection | Random per-request code fence + "untrusted data" system-prompt rules |
| Config | `.aegisscan.toml` (`exclude_dirs`); Bandit no longer silently skips `tests/`/`examples/` |
| Languages | Tree-sitter chunking for Go, Java, PHP, C# (plus Python/JS/TS) |
| Misc | History uses `executemany`; SARIF reports real duration, placeholder URL removed; CI installs Gitleaks binary + runs tests with coverage gate; packaging limited to `scanner*` with package-data |

---

## 2. Remaining issues

### P0 — do first
1. **Rotate the Groq keys in `.env`** (`GROQ_API_KEY`, `GROQ_API_KEY1`). They live in a plain file in the project folder. `.env` is git-ignored and untracked, but rotate if the folder was ever zipped, shared or synced. `GROQ_API_KEY1` is not read by any code — delete it or decide on multi-key support (see P2; check Groq ToS first).
2. **Merge the branch.** `fix/server-hardening` has not been merged into `main`. Review the 4 commits (`git log main..fix/server-hardening`), then merge or open a PR.

### P1 — real gaps
3. **Web UI progress is coarse.** The SSE stream reports honest phases only (crawl → "analysing N files" → complete). Real per-file/per-phase progress needs a progress callback threaded through `main.run()` (`scanner/server/app.py` consumes it).
4. **SQL has no grammar.** `.sql` files use the generic chunker. No maintained tree-sitter SQL package was found/trusted. Options: evaluate `tree-sitter-sql` variants, or add a statement-splitting chunker.
5. **Optimizer is Python-only.** JS/TS/Go/Java get performance signal only from Semgrep rules (name-matched in `semgrep_runner._infer_category`) and the LLM. Consider tree-sitter-based equivalents of OPT001–OPT004.
6. **Optimizer heuristics are conservative and name-based.** `_DB_METHODS` (`execute`, `fetchone`, `query`, …) and `_HTTP_OWNERS` (`requests`, `httpx`, `session`, `client`) can miss ORMs (`.filter()`, `.objects.get()`) and flag non-DB `.query()` methods. Tune with real-repo runs.
7. **Benchmark is small and self-authored.** `examples/slow_python` (8 expected issues) + `examples/tricky_clean_python` give P/R = 1.0 by construction. Plan §7 wants confidence calibration, JSON validity rate and latency per chunk measured on a larger labelled set (ideally real CVE-style samples for the security side too).
8. **No linter / type-check gate.** `ruff`/`mypy` were not added because enabling them means cleaning up existing warnings first. Suggested: add `ruff` with a baseline config, fix, then gate in CI.
9. **Coverage hot spots:** `scanner/server/app.py` (~49%, SSE path untested), `semgrep_runner.py` (~47%), `gitleaks_runner.py` (~55%), `git_diff.py` (~61%), `ollama_provider.py` (~70%), `patcher.py` (~67%).
10. **Built UI is not committed.** `dist/` is in `.gitignore`, so `scanner/server/dist` is absent in a fresh clone → run `npm ci && npm run build` in `scanner/server/ui/`. Decide: commit the build, build in CI, or document it (README currently doesn't mention the UI build).
11. **Node/JS assets live inside the Python package tree** (`scanner/server/ui/node_modules`). Harmless for git (ignored) but bloats the working directory; consider moving `ui/` to the repo root.

### P2 — design decisions / nice to have
12. **Multi-credential pooling** (plan V5) is not implemented. Verify Groq's ToS before adding.
13. **Prompt-injection defence is mitigation, not proof.** No adversarial test corpus exists that exercises a real model. Add a set of injection samples and assert the model output still reports the real vulnerability.
14. **Static-tool findings are inserted into the prompt unescaped** (`build_user_prompt` "Static Analysis Findings" section). Tool-authored text is lower risk than scanned code but is still not fenced.
15. **`--changed-only` and git features** are only lightly tested (`git_diff.py` 61%). The folder was not a git repo until this session; test on a real repo with history.
16. **Line endings:** files are CRLF in the working tree; git warns "LF will be replaced by CRLF". Consider adding a `.gitattributes` (`* text=auto`).
17. **`.security-baseline.json`** at the repo root fingerprints `examples/vulnerable_python`. It is inert unless `--baseline` is passed, but it is a stale artefact; consider deleting or moving it under `examples/`.
18. **Groq model list will rot again.** Consider fetching `client.models.list()` on first use and intersecting it with the configured list.

---

## 3. How to test

Always use the project venv. From the project root (`D:\AI_Projects\AI-Driven_Workspace_Security_&_Optimization_Scanner`):

```powershell
.venv\Scripts\python.exe -m pytest -q -o addopts="" -p no:cacheprovider
```

- Full suite takes ~90–110 s (several tests run Bandit/Semgrep on the examples).
- With coverage and the CI gate:
  ```powershell
  .venv\Scripts\python.exe -m pytest -q -o addopts="" --cov=scanner --cov-report=term-missing --cov-fail-under=75
  ```
- Single areas:

| Area | Command |
|---|---|
| Server hardening | `pytest tests/test_v10_server.py` |
| Optimizer, config, OpenAI, redaction, prompt fence | `pytest tests/test_v11_hardening.py` |
| Languages, concurrency, optimizer P/R, Groq failover, SARIF, history batch, live providers | `pytest tests/test_v12_remaining.py` |

### Live-provider smoke tests (opt-in)
`tests/test_v12_remaining.py::test_live_*` are skipped unless credentials/daemon exist:
- `GROQ_API_KEY` set → real Groq call. **Note:** running the whole suite loads `.env` (via `main.py`'s `load_dotenv`), so these run — and spend a tiny amount of quota — in full runs. Run alone they skip unless you export the key first.
- `OPENAI_API_KEY` set → real OpenAI call (never yet run).
- Ollama daemon on `localhost:11434` → real local call (never yet run).

### Manual checks worth doing before merging
1. **CLI scan:** `.venv\Scripts\python.exe main.py examples\vulnerable_python --static-only` → Bandit findings; `main.py examples\slow_python --static-only` → 8 `aegis-opt` performance findings and a reduced optimization score.
2. **LLM pass:** `main.py examples\vulnerable_python` (needs a valid key) → `llm_provider` set, LLM findings present, no "model unavailable" warnings.
3. **Server:** `main.py --server`, open `http://localhost:8000`, run a scan of a folder inside the project (works) and one outside (403 unless `AEGISSCAN_ALLOWED_ROOTS` is set). Confirm `curl -H "Origin: https://evil.example" http://127.0.0.1:8000/api/history` → 403 and no `Access-Control-Allow-Origin` header.
4. **Vite dev proxy:** `npm run dev` in `scanner/server/ui/` (port 5173, proxies `/api` → `127.0.0.1:8000`) with the server running.
5. **CI:** push the branch to GitHub and confirm `.github/workflows/security-scan.yml` succeeds (Gitleaks install step, `pip install ".[static,dev]"`, tests, coverage gate, scan). This workflow has **never been run**.

### Known environment quirks (Windows dev box)
- Git Bash heredocs containing many quotes can fail to parse; prefer writing scripts to files.
- `find`/`Glob` over the project descend into `.venv` and `scanner/server/ui/node_modules` — scope searches to `scanner`, `tests`, `examples`.
- Files use CRLF; when scripting edits preserve line endings.
