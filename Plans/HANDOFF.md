# AegisScan — handoff for the next session

_Written 2026-11-24 at the end of a long session. Read this first, then `Plans/REMAINING_ISSUES_AND_TESTING.md` (the detailed issue list, items 1–30) and `HOW_IT_WORKS.md`._

## 1. Snapshot

**What it is:** a hybrid security + optimization scanner. Bandit, Semgrep, Gitleaks and a built-in Python optimizer run first; a Groq LLM pass reasons over the code and the static findings; results go to CLI, HTML, JSON and SARIF, a React web UI (`ui/`), and a CI gate (`--fail-on security:high`).

**Repo:** `github.com/KULLOLLITARUN/aegisscan`, branch `main` (default). Local working copy: `D:\AI_Projects\AI-Driven_Workspace_Security_&_Optimization_Scanner`.

**State at handoff**
- `main` is at `78a5713` (CI audit summary). Ten consecutive pushes to `main` are green (`security-scan` + `ui-build`), plus the green pull-request run #28. The run for `78a5713` is #29, also green (1m 43s).
- Tests: 818 passed, 3 skipped, coverage 93% (gate 75%). ruff and mypy clean.
- Benchmark (static-only, Semgrep on, 155 labels / 51 files): precision 91.0%, in-scope recall 100% (146 labels, 0 missed), recall over all labels 95.5%; the 7 labels left need the LLM. ECE 0.176 (got worse from 0.146 when the language rules landed; not investigated). Semgrep-off baseline gated by tests: precision 86.5%, in-scope recall 100%.
- Open pull request #1 (`ci-pr-path-test`, one docstring line in `scope.py`) exists only to test the CI pull-request path. Its run (#28) passed.

## 2. What this session built (all on `main`, details in the plans doc)

| Area | Result |
|---|---|
| CI | Green for the first time; mypy fix; failed-test annotations; Actions bumped to Node 24 (v7); **audit step fixed**: it used `--changed-only` on a clean checkout and scanned nothing, now uses `--changed-since <ref>`; audit summary written to the run page (base ref, files analysed, findings, gate verdict). |
| Scanner | Gitleaks + built-in secret scanner merged (item 26); `--changed-only` really scans only changed files (item 25); `--changed-since REF` (item 30); `exclude_dirs` now applies to all four tools (item 29); `gitleaks:allow` marker. |
| Rules | Bundled Semgrep rules per language in `scanner/static_analysis/rules/*_security.yml`: JS/TS (round 2), Java, Go, PHP, C#. |
| Benchmark | 129 → 155 labels; new fixtures `more_sinks.*` + safe twins. The 10 labels the registry packs missed in Java/Go/PHP/C# were written before the rules, so they are the independent test; the 26 newest labels were written alongside the rules. |
| Docs | README, HOW_IT_WORKS, plans doc all updated. |

## 3. Open items, in suggested order

1. **Confirm the audit summary on the real run (not yet seen by anyone).** Run #29 passed, but the summary text could not be read from outside: GitHub renders job summaries client-side and neither the unauthenticated web pages nor the REST API expose it, so do not spend time scraping. Ask the user to open https://github.com/KULLOLLITARUN/aegisscan/actions and the run for `78a5713`; the summary page should show "AegisScan audit", the base ref, "Files analysed", findings and the gate line. If the section is missing or the numbers look wrong, the step `Audit summary` in `.github/workflows/security-scan.yml` is the place (log is kept in `$RUNNER_TEMP/audit.log`, deliberately outside the checkout).
2. **Housekeeping:** close PR #1 without merging, delete the remote branch `ci-pr-path-test`, and delete the local safety branches `backup-before-trailer-removal`, `backup-pr-before-trailer-removal` and `ci-pr-path-test` (old history with trailers). Needs the user's say-so for anything remote.
3. **Contributors box still lists "Claude".** GitHub's Insights graph is already clean; the repo-page sidebar is a separate cache that did not refresh after a default-branch flip. Give it a day; if it persists, draft a GitHub Support request (it can also purge the old commit SHAs, which are still reachable by URL).
4. **Tool ideas the user asked about** (research done 2026-11-24, search-verified items marked ✔):
   - **SCA is the biggest functional gap** — no dependency-vulnerability scanning at all. OSV-Scanner ✔ (Apache-2.0) as a subprocess runner like Gitleaks, plus pip-audit as a Python cross-check. It sends package names/versions to OSV, so `--privacy strict` must disable it.
   - Config/IaC/workflow scanning: zizmor (GitHub Actions), Hadolint (Dockerfile; GPL-3.0, run as a subprocess, do not bundle), Checkov or Trivy (render.yaml, IaC). Dogfood on this repo's own workflow/Dockerfile.
   - OpenGrep ✔ (LGPL-2.1 Semgrep fork; adds cross-function taint via `--taint-intrafile`, not cross-file). Cheap experiment: swap the binary, re-run `python main.py --benchmark --static-only`, adopt only if the numbers improve.
   - promptfoo ✔ (MIT) or garak ✔ (Apache-2.0) to close plans item 13 (prompt-injection tests against a live model).
   - Joern ✔ (code property graph, cross-file taint; Apache-2.0 per a mirror, verify the LICENSE file) — large effort, later. "graphify" was discussed and judged a developer tool, not a scanner feature; nothing was installed.
   - Small wins: upload our SARIF to GitHub code scanning; Ruff `S`/`PERF` rules; GuardDog for malicious packages.
   - License check before any hosted/commercial use: the Semgrep registry packs we load (`p/python`, `p/owasp-top-ten`, …) are under the Semgrep Rules License.
5. **Known weaknesses** (see plans doc): ECE worsened (above); prompt-injection defence untested live (item 13); LLM-only misses; no cross-file analysis (a change can introduce an issue visible only together with an unchanged file); request-driven rules match direct use only (no taint through variables); `--changed-since` scans nothing extra when a ref is unknown only by falling back to a full scan.
6. **One behaviour to decide:** since the audit step now scans real files, the LLM pass runs in CI whenever the `GROQ_API_KEY` secret is set, which sends a PR's changed files to Groq. It never ran before. Keep, or force `--static-only` in CI?

## 4. Decisions already made — do not reopen without asking

- **No Render deployment.** `render.yaml`, the Dockerfile and `Plans/RENDER_DEPLOY_CHECKLIST.md` stay in the repo untouched. Hosted mode and the Cloudflare tunnel launcher were not ruled out.
- **Never add `Co-Authored-By: Claude` or any Claude attribution** to commits or PR text (saved in memory too). The 12 earlier commits were rewritten and force-pushed with the user's explicit approval.
- `exclude_dirs` applies to every tool (a behaviour change for anyone who sets it).
- Bundled rules are deliberately light: direct uses only, with guarded safe twins in the benchmark.

## 5. How this user likes to work

- Asks for a change, reviews the summary, then says "commit and push it" — **do not commit or push before being told**, and check CI after every push.
- Force-push, deleting remote branches, installing third-party tools and anything touching credentials need an explicit go-ahead; the permission layer may block them anyway, and workarounds are not wanted.
- Prefers honest reporting: say what was measured, what was only inferred, and what could not be checked.

## 6. Environment quirks

- Windows 11; use the venv: `.venv\Scripts\python.exe` (Git Bash path `.venv/Scripts/python.exe`). Tests: `python -m pytest -q -p no:cacheprovider` (~110 s); with CI's coverage gate add `--cov=scanner --cov-fail-under=75`. Lint: `python -m ruff check .`, types: `python -m mypy`.
- CI has the real Gitleaks binary; the dev box does not. To reproduce CI locally, put a Gitleaks 8.21.2 binary on `PATH` (a copy was downloaded to the session scratchpad and may be gone). The benchmark fixture pins the built-in scanner so results do not depend on it.
- Semgrep needs network (registry packs). WSL is broken on this machine (missing disk image), so Linux-only failures show up only in CI; a failed-test annotations step prints them.
- **No `gh` CLI and no GitHub token.** The unauthenticated API allows 60 calls/hour and was exhausted repeatedly; read run results from GitHub's web pages (`/actions`, `/actions/runs/<id>`) instead. Job logs need a login. The user opens PRs themselves (a pre-filled compare URL works).
- Many source files use CRLF; use the Edit tool or write with explicit newlines rather than shell heredocs. Git Bash heredocs with many quotes break; write scripts to files.
- Long commands may be auto-backgrounded; their output lands in the task output file.

## 7. First things to do

```
git fetch && git status -sb              # expect main == origin/main at 78a5713 or later
python -m pytest -q -p no:cacheprovider  # expect 818 passed, 3 skipped
```
Then open item 1 above, and ask the user which of item 4 to start with (OSV-Scanner first is my recommendation).
