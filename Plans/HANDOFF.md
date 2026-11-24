# AegisScan — handoff for the next session

_Written 2026-11-24 at the end of a long session. Read this first, then `Plans/REMAINING_ISSUES_AND_TESTING.md` (the detailed issue list, items 1–30) and `HOW_IT_WORKS.md`._

## 1. Snapshot

**What it is:** a hybrid security + optimization scanner. Bandit, Semgrep, Gitleaks and a built-in Python optimizer run first; a Groq LLM pass reasons over the code and the static findings; results go to CLI, HTML, JSON and SARIF, a React web UI (`ui/`), and a CI gate (`--fail-on security:high`).

**Repo:** `github.com/KULLOLLITARUN/aegisscan`, branch `main` (default). Local working copy: `D:\AI_Projects\AI-Driven_Workspace_Security_&_Optimization_Scanner`.

**State at handoff**
- `main` is still at `d11b2d2` (docs only on top of `78a5713`). All new work is on branch `feat/osv-dependency-scanning`, ahead of it by the commits in the open pull request. Its CI run (#31, on `1c52463`) passed both jobs (`security-scan`, `ui-build`); job logs and the run summary page could not be read without a login.
- Tests: 870 passed, 3 skipped, coverage 93% (gate 75%), with the real OSV-Scanner on PATH. ruff and mypy clean.
- Benchmark (static-only, Semgrep on, 155 labels / 51 files): precision 91.0%, in-scope recall 100% (146 labels, 0 missed), recall over all labels 95.5% (the 7 left need the LLM). ECE 0.131, Brier 0.087 (was 0.176 and 0.105 before the per-rule confidence work; the gain is partly fitted to this corpus).
- Open pull request #1 (`ci-pr-path-test`, one docstring line in `scope.py`) exists only to test the CI pull-request path. Its run passed.

## 2. What has been built (first the earlier session on `main`, then branch `feat/osv-dependency-scanning`; details in the plans doc)

| Area | Result |
|---|---|
| CI | Green for the first time; mypy fix; failed-test annotations; Actions bumped to Node 24 (v7); **audit step fixed**: it used `--changed-only` on a clean checkout and scanned nothing, now uses `--changed-since <ref>`; audit summary written to the run page (base ref, files analysed, findings, gate verdict). |
| Scanner | Gitleaks + built-in secret scanner merged (item 26); `--changed-only` really scans only changed files (item 25); `--changed-since REF` (item 30); `exclude_dirs` now applies to all four tools (item 29); `gitleaks:allow` marker. |
| Rules | Bundled Semgrep rules per language in `scanner/static_analysis/rules/*_security.yml`: JS/TS (round 2), Java, Go, PHP, C#. |
| Benchmark | 129 → 155 labels; new fixtures `more_sinks.*` + safe twins. The 10 labels the registry packs missed in Java/Go/PHP/C# were written before the rules, so they are the independent test; the 26 newest labels were written alongside the rules. |
| Docs | README, HOW_IT_WORKS, plans doc all updated. |
| Branch: dependencies | OSV-Scanner runner (`osv_runner.py`, category `dependencies`, source `osv`), skipped under `--privacy strict`, scoped to changed lockfiles in `--changed-*` runs. vite upgraded 8.2.1 to 8.3.8 to clear the 7 advisories it found on this repo. |
| Branch: CI | Actions pinned to commit SHAs, `permissions: contents: read`, `persist-credentials: false`, pinned and checksum-verified OSV-Scanner install; zizmor 1.22.0 reports no findings. |
| Branch: confidence | Per-rule `aegis_confidence` on all 38 bundled rules (a quoted string, because Semgrep rejects float metadata), Semgrep WARNING default 0.75. ECE 0.176 to 0.131. |
| Branch: UI | All 14 categories and readable tool names; CSS-only animation of scan steps and severity counts. |

## 3. Open items, in suggested order

1. **Confirm the audit summary on the real run (not yet seen by anyone).** Run #29 (and the pull-request run #31) passed, but the summary text could not be read from outside: GitHub renders job summaries client-side and neither the unauthenticated web pages nor the REST API expose it, so do not spend time scraping. Ask the user to open https://github.com/KULLOLLITARUN/aegisscan/actions and the run for `78a5713`; the summary page should show "AegisScan audit", the base ref, "Files analysed", findings and the gate line. If the section is missing or the numbers look wrong, the step `Audit summary` in `.github/workflows/security-scan.yml` is the place (log is kept in `$RUNNER_TEMP/audit.log`, deliberately outside the checkout).
2. **Housekeeping:** close PR #1 without merging, delete the remote branch `ci-pr-path-test`, and delete the local safety branches `backup-before-trailer-removal`, `backup-pr-before-trailer-removal` and `ci-pr-path-test` (old history with trailers). Needs the user's say-so for anything remote.
3. **Contributors box still lists "Claude".** GitHub's Insights graph is already clean; the repo-page sidebar is a separate cache that did not refresh after a default-branch flip. Give it a day; if it persists, draft a GitHub Support request (it can also purge the old commit SHAs, which are still reachable by URL).
4. **Tool ideas the user asked about** (research done 2026-11-24, search-verified items marked ✔):
   - **Done on the branch: SCA.** OSV-Scanner v2.7.1 runs as a subprocess and in CI (pinned, checksum-verified). Still open: pip-audit as a Python cross-check (use `--no-deps --disable-pip`; its docs say `pip-audit -r` behaves like `pip install -r`), a baseline for dependency findings, and a separate `dependencies:high` gate spec (today any non-performance category counts under `--fail-on security:high`).
   - Config/IaC/workflow scanning: **zizmor done** (1.22.0, offline, newest release with a PyPI attestation; newer ones had none, reason unknown; not yet run in CI). Hadolint (Dockerfile; GPL-3.0, subprocess only, verify its releases first) is next. **Trivy and KICS are rejected**: Aqua's Trivy had a supply-chain compromise in March 2026 (see decisions below).
   - OpenGrep ✔ (LGPL-2.1 Semgrep fork; adds cross-function taint via `--taint-intrafile`, not cross-file). Cheap experiment: swap the binary, re-run `python main.py --benchmark --static-only`, adopt only if the numbers improve.
   - promptfoo ✔ (MIT) or garak ✔ (Apache-2.0) to close plans item 13 (prompt-injection tests against a live model).
   - Joern ✔ (code property graph, cross-file taint; Apache-2.0 per a mirror, verify the LICENSE file) — large effort, later. "graphify" was discussed and judged a developer tool, not a scanner feature; nothing was installed.
   - Small wins: upload our SARIF to GitHub code scanning; Ruff `S`/`PERF` rules; GuardDog for malicious packages.
   - License check before any hosted/commercial use: the Semgrep registry packs we load (`p/python`, `p/owasp-top-ten`, …) are under the Semgrep Rules License.
5. **Known weaknesses** (see plans doc): ECE improved to 0.131 but the gain is partly fitted to the benchmark, so check it on real repositories; prompt-injection defence untested live (item 13); LLM-only misses; no cross-file analysis (a change can introduce an issue visible only together with an unchanged file); request-driven rules match direct use only (no taint through variables); `--changed-since` scans nothing extra when a ref is unknown only by falling back to a full scan.
6. **One behaviour to decide:** since the audit step now scans real files, the LLM pass runs in CI whenever the `GROQ_API_KEY` secret is set, which sends a PR's changed files to Groq. It never ran before. Keep, or force `--static-only` in CI?
7. **Other ideas, not started:** out-of-sample calibration check on real open-source repositories; Dependabot or Renovate for the pinned action SHAs and the OSV version; zizmor in CI (pinned and hashed); SARIF upload to GitHub code scanning; the pin-drop animation on the canvas; a dependencies view in the UI; a PR comment summary; a browser UI test (there is none, which is how the "Other" category bug went unnoticed).

## 4. Decisions already made — do not reopen without asking

- **No Render deployment.** `render.yaml`, the Dockerfile and `Plans/RENDER_DEPLOY_CHECKLIST.md` stay in the repo untouched. Hosted mode and the Cloudflare tunnel launcher were not ruled out.
- **Never add `Co-Authored-By: Claude` or any Claude attribution** to commits or PR text (saved in memory too). The 12 earlier commits were rewritten and force-pushed with the user's explicit approval.
- **Only vetted open-source tools** (the user's instruction, saved in memory too). Checklist: OSI licence, reputable maintainer, verifiable releases (attestation or a pinned hash), a search for security incidents, no execution of scanned code, note what data leaves the machine; pin by exact version and hash (commit SHA for Actions). Ask before installing anything.
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
- **No `gh` CLI and no GitHub token.** The unauthenticated API allows 60 calls/hour and was exhausted repeatedly; read run results from GitHub's web pages (`/actions`, `/actions/runs/<id>`) instead. Job logs need a login. The user opens PRs themselves (a pre-filled compare URL works). The unauthenticated REST endpoint `/repos/<owner>/<repo>/actions/runs/<id>/jobs` does return every job and step with its conclusion (no log text), which is enough to see which steps ran and passed; `.../actions/runs?branch=<name>` lists runs. Two calls per check are cheap.
- Many source files use CRLF; use the Edit tool or write with explicit newlines rather than shell heredocs. Git Bash heredocs with many quotes break; write scripts to files.
- Long commands may be auto-backgrounded; their output lands in the task output file.

## 7. First things to do

```
git fetch && git status -sb              # main is at d11b2d2; work is on origin/feat/osv-dependency-scanning (PR open)
python -m pytest -q -p no:cacheprovider  # expect 870 passed, 3 skipped (OSV-Scanner and Semgrep on PATH)
```
Then read the audit summary on the PR run (item 1), merge or follow up the PR (the user merges; do not merge it), and ask which item to start with. My recommendation: the out-of-sample calibration check, then pip-audit, SARIF upload and Dependabot as one small PR.
