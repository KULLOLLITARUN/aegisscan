# AegisScan — Remaining Issues & Testing Guide

_State as of 2026-09-29. Branch: `fix/server-hardening` (4 commits on top of the `main` baseline, not merged)._
_Test status: 351 passed, 4 skipped, coverage 90% (gate: 75%)._

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
| Coverage | `tests/test_v13_coverage.py` (34 tests, mocked): SSE stream, error/strict-privacy paths, log forwarding, sync-scan errors, Semgrep and Gitleaks runners incl. fallbacks. `semgrep_runner` 99%, `gitleaks_runner` 89% |
| Lint | `ruff` added (`[tool.ruff]` in pyproject: E4/E7/E9, F, B, I; `examples/` and `ui/` excluded; `main.py` ignores E402/E701 by design). Baseline cleaned (unused imports, import order, f-strings, ambiguous `l`, frozen-model test now expects `ValidationError`); `manager.py` binds the provider explicitly in the retry closure. CI runs `ruff check .` before tests. Locally: `python -m ruff check .` (inside the venv) |
| SQL chunking | `scanner/chunking/sql_chunker.py`: statement-aware splitter (no grammar). Respects strings/identifiers/comments (nested), Postgres `$tag$` quoting, MySQL `DELIMITER`, T-SQL `GO`, and `BEGIN/CASE...END` routine bodies; routines are their own chunk (`symbol_type=function`), small statements pack into <=50-line chunks, oversized statements are never cut. Falls back to the generic chunker on failure. `tests/test_v17_sql_chunker.py` (23 tests). Known limits: bare Oracle PL/SQL `/` terminators and exotic quoting are not modelled |
| Optimizer JS/TS | `scanner/static_analysis/optimization_js.py` (tree-sitter): OPT001-OPT004 for `.js/.jsx/.mjs/.cjs/.ts/.tsx` (DB/ORM: db.query, Mongoose/Sequelize/Prisma/TypeORM/Knex; network only when *awaited* in a real loop so `Promise.all(xs.map(fetch))` is not flagged; `+=` strings; nested loop/`forEach` over same collection; `new RegExp("literal")`). Skips `.min.js`, `.d.ts`, excluded dirs. Fixtures `examples/slow_js` (6 expected) and `examples/tricky_clean_js` (0). `tests/test_v16_optimizer_js.py` (40 tests). Go/Java/PHP/C# still rely on Semgrep + LLM |
| Optimizer ORM heuristics | OPT001 is chain-aware: Django `Model.objects...`, SQLAlchemy `session.query(...)`/`get(Model, pk)`/`scalars`, network calls via `self.client`/`urlopen`. `.query()` only counts on DB-like owners; ambiguous HTTP owners (`session`, `client`) need URL-like evidence, so `session.get('key')` and `parser.query()` are no longer flagged. ORM hits use confidence 0.6 and ORM-specific fixes. `tests/test_v15_optimizer_orm.py` (32 tests). Lazy related-manager access (`user.orders.all()`) is still undetectable statically |
| Progress | `main.run(progress=cb)` calls `cb(phase, pct, detail)` per phase; static tools and each LLM chunk report too (`run_all_tools(progress=)`, `analyze_chunks(progress=)`). SSE forwards them; the server no longer pre-crawls or fakes phases. Callback errors are swallowed. `tests/test_v14_progress.py` (7 tests) |
| Misc | History uses `executemany`; SARIF reports real duration, placeholder URL removed; CI installs Gitleaks binary + runs tests with coverage gate; packaging limited to `scanner*` with package-data |

---

## 2. Remaining issues

### P0 — do first
1. **Rotate the Groq keys in `.env`** (`GROQ_API_KEY`, `GROQ_API_KEY1`). They live in a plain file in the project folder. `.env` is git-ignored and untracked, but rotate if the folder was ever zipped, shared or synced. `GROQ_API_KEY1` is not read by any code — delete it or decide on multi-key support (see P2; check Groq ToS first).
2. **Merge the branch.** `fix/server-hardening` has not been merged into `main`. Review the 4 commits (`git log main..fix/server-hardening`), then merge or open a PR.

### P1 — real gaps
7. **Benchmark is small and self-authored.** `examples/slow_python` (8 expected issues) + `examples/tricky_clean_python` give P/R = 1.0 by construction. Plan §7 wants confidence calibration, JSON validity rate and latency per chunk measured on a larger labelled set (ideally real CVE-style samples for the security side too).
8. **No type-check gate.** `ruff` is now gated in CI (see section 1) but `mypy` is not. Adding it means fixing the existing type errors first; widen the ruff rule set (UP, SIM, BLE) deliberately later.
9. **Coverage hot spots (remaining):** `git_diff.py` (~61%), `ollama_provider.py` (~70%), `patcher.py` (~67%). `server/app.py`, `semgrep_runner.py` and `gitleaks_runner.py` are now covered (see section 1).
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
| SSE path, Semgrep/Gitleaks runners | `pytest tests/test_v13_coverage.py` |
| Progress callback (run, static tools, auditor, SSE) | `pytest tests/test_v14_progress.py` |
| Optimizer ORM heuristics | `pytest tests/test_v15_optimizer_orm.py` |
| Optimizer JS/TS | `pytest tests/test_v16_optimizer_js.py` |
| SQL chunker | `pytest tests/test_v17_sql_chunker.py` |

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
