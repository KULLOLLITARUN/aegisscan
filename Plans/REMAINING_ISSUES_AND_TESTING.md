# AegisScan — Remaining Issues & Testing Guide

_State as of 2026-09-29. Branch: `fix/server-hardening` (4 commits on top of the `main` baseline, not merged)._
_Test status: 414 passed, 4 skipped, coverage 92% (gate: 75%)._

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
| UI shipping | Decision: the build output (`scanner/server/dist`) stays uncommitted (hashed files would churn every rebuild). README now documents `npm ci && npm run build` (Node 22+) and a Windows caveat; the server prints a reminder and serves the basic fallback page when `dist/` is absent (`_ui_build_hint`); CI has a new `ui-build` job (npm ci, lint, build, upload `aegisscan-ui-dist`). The UI build and lint were verified locally by calling vite/oxlint through node (lint: 2 warnings, exit 0; build reproduces the same hashed files). The `ui-build` job itself has never run |
| CI test bug | `test_server_dashboard_route` asserted text that only exists in the gitignored React build, so it failed on any fresh clone / CI (confirmed by running the old test with `dist/` hidden). Now hermetic; 4 more tests cover the fallback page and the reminder |
| README | Replaced the fabricated benchmark output and the stale 183-test count with real figures |
| Benchmark | Replaced the tautological benchmark (every finding counted as a TP, expected count `max(4, tp)`, so recall was always 1.0). Now `examples/benchmark_labels.json` holds ground truth written by reading the code: 31 files (15 clean), 88 labels, incl. a new CVE-style `examples/benchmark_corpus/` (7 vulnerable + 4 safe look-alike files). `scanner/evaluation/benchmark.py` reports precision, recall (in scope of the active tools, and over all labels), FPR, per-source precision, per-category recall, calibration bins + ECE + Brier, and for LLM runs JSON validity rate and latency/request. `main.py --benchmark [--benchmark-json FILE]`. Baseline (Bandit + Gitleaks fallback + optimizer, Semgrep off): precision 86%, in-scope recall 100% (75% of all labels; the rest need Semgrep/LLM), 3/15 clean files flagged, ECE 0.14, Brier 0.11. `tests/test_v18_benchmark.py` (27 tests) gates recall >= 0.95, precision >= 0.80, ECE/Brier <= 0.20. `tests/test_v7_benchmark.py` was removed: it asserted the fake metrics |
| Deduplicator bug | Found by the benchmark: findings in the same file+category within 5 lines were merged, so two distinct SQLi/MD5/pickle hits a few lines apart collapsed into one (in-scope recall 81% -> 97%). Now a finding never joins a cluster that already holds a *different* finding from its own source; cross-source merging is unchanged. Regression tests in `tests/test_intelligence.py` and `test_v18_benchmark.py` |
| Confidence calibration | Bandit B401-B415 (import-only checks) now carry confidence 0.30: 0 of 6 were real issues on the benchmark although Bandit reported them at 0.85 (Brier 0.153 -> 0.106). Nothing else was tuned: 84 findings from a self-authored corpus is too small to fit further. Bandit B101 (assert) stays skipped on purpose, so the two assert-as-auth labels are LLM-only |
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
7. **Benchmark is still small and self-authored.** 88 labels / 31 files; calibration bins hold only 1-47 findings each. Remaining work: (a) run it once with a live LLM (`main.py --benchmark`, needs a key) to record JSON validity and latency per request, which have never been measured; (b) done: Semgrep now scores (see environment notes); (c) add real CVE-derived samples and other languages; (d) measured precision on safe look-alikes is imperfect by design (Bandit flags `IN (?,?)` placeholder SQL and allow-listed `ORDER BY`), so don't treat the current 86% as a ceiling to game.
8. **No type-check gate.** `ruff` is now gated in CI (see section 1) but `mypy` is not. Adding it means fixing the existing type errors first; widen the ruff rule set (UP, SIM, BLE) deliberately later.
9. **Coverage hot spots (remaining):** `ollama_provider.py` (~36% in isolation). Deliberately not being worked on: the project uses Groq; Ollama stays in the failover chain untouched. `git_diff.py` and `patcher.py` are now 100% (`tests/test_v19_git_diff_patcher.py`, 29 tests); `server/app.py`, `semgrep_runner.py` and `gitleaks_runner.py` were covered earlier (see section 1). Known gap found while testing: the patcher's `os.system` -> `subprocess.run` replacement is unreachable on its own (the branch needs "subprocess" in the line or issue type), so a bare `os.system(cmd)` gets the generic template. The older V8 patcher test passes a tuple as the LLM response, which raises inside the try block, so it only ever exercised the fallback.
11. **Node/JS assets live inside the Python package tree** (`scanner/server/ui/node_modules`). Harmless for git (ignored) but bloats the working directory; consider moving `ui/` to the repo root.

### P2 — design decisions / nice to have
12. **Multi-credential pooling** (plan V5) is not implemented. Verify Groq's ToS before adding.
13. **Prompt-injection defence is mitigation, not proof.** No adversarial test corpus exists that exercises a real model. Add a set of injection samples and assert the model output still reports the real vulnerability.
14. **Static-tool findings are inserted into the prompt unescaped** (`build_user_prompt` "Static Analysis Findings" section). Tool-authored text is lower risk than scanned code but is still not fenced.
15. **`--changed-only` and git features:** `get_changed_files` is now tested against a real temporary repo (modified, untracked, staged, renamed, deleted) plus mocked failure paths. Still untested: the `--changed-only` wiring in `main.py` end to end, and a repo with no commits yet (`git diff HEAD` fails there; the code skips it, so only `git status` results are used; not tested).
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
| Dashboard route, fallback page, build reminder | `pytest tests/test_v10_server.py` |
| Labelled benchmark, dedup regression, JSON-validity telemetry | `pytest tests/test_v18_benchmark.py tests/test_intelligence.py` |
| Print the benchmark report | `python main.py --benchmark --static-only` (inside the venv) |

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
- The project path contains `&` (`Security_&_Optimization`), so `npm run ...` fails under cmd.exe (npm reports `Cannot find module` for vite or oxlint). Call the tools through node instead: `node node_modules/vite/bin/vite.js build`, `node node_modules/oxlint/bin/oxlint`. Do not run `npm ci` here (it wipes node_modules and would hit the same problem).
- Semgrep zero-findings cause found and fixed: `p/owasp-top-10` no longer exists on the registry (HTTP 404, correct id `p/owasp-top-ten`), and one invalid config makes Semgrep exit 7 with no results, so all five packs were lost silently. The runner now logs Semgrep `errors` as warnings. With the fix, `--benchmark --static-only`: Semgrep 25/28 correct (89%), precision 87%, in-scope recall 88.9%, recall over all labels 83%. Remaining misses are mostly JS xss/injection labels that the p/javascript packs do not match. Watch for further registry renames (see P2 item 18).
- Fixed: the CLI crashed printing non-cp1252 characters (e.g. U+2011 in a finding) on a default Windows console. `main._make_console_safe()` now sets `errors="replace"` on stdout/stderr at startup.
- `main.py --benchmark` without `--static-only` makes live LLM requests (~75 per run).
