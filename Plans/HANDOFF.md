# AegisScan — handoff for the next session

_Updated 2026-11-24 after the real-repository round. Read this first, then `Plans/REMAINING_ISSUES_AND_TESTING.md` (the detailed issue list and fixed-items table) and `HOW_IT_WORKS.md`._

## 1. Snapshot

**What it is:** a hybrid security + optimization scanner. Bandit, Semgrep, Gitleaks, OSV-Scanner and a built-in optimizer run first; a Groq LLM pass reasons over the code and the static findings; results go to CLI, HTML, JSON and SARIF, a React web UI (`ui/`), and a CI gate (`--fail-on security:high`).

**Repo:** `github.com/KULLOLLITARUN/aegisscan`, branch `main` (the only remote branch). Local working copy: `D:\AI_Projects\AI-Driven_Workspace_Security_&_Optimization_Scanner`.

**State at handoff**
- `main` at `c6cd1c3` (merge of five branches on top of `c6102d0`). Everything is merged and pushed; there are no open pull requests. About 15 old local branches from earlier sessions are still around and can be deleted.
- Tests: 925 passed, 3 skipped. ruff and mypy clean. Not yet seen: the CI run on this `main` (first run of the new workflow, see item 1 below).
- Benchmark (static-only, Semgrep on, 162 labels / 55 files, 27 clean): precision 90.3%, recall 100% over the 154 in-scope labels and 95.7% over all 162, 6 of 27 clean files flagged, ECE 0.122, Brier 0.092.

## 2. What was done in the real-repository round

Scanned eight public repositories (static-only, so no code left the machine): Flask, Express, Gin, Django, spring-petclinic (mature or clean) and NodeGoat, DVWA, pygoat (intentionally vulnerable). Each round of triage found a real problem, fixed on `main`:

| Problem found | Fix |
|---|---|
| One tool reporting one line through several rules (45 of Express's 88 findings) | `deduplicator._collapse_same_spot`: same tool, file and exact lines collapse to the most severe; the catch-all `best_practices` category is compatible with any other |
| Findings in `tests/`, `examples/`, `docs/` dominating the high count | `intelligence/context.py` `weight_by_context`: one severity level lower and half confidence, judged relative to the scan target |
| NoSQL `$where` injection missed (NodeGoat) | bundled rule `aegis-js-mongo-where-injection` |
| PHP open redirect missed (`header ("location: " . $_GET[..])`, DVWA) | the rule now matches the literal case-insensitively |
| GitHub Actions "mutable tag" notes dominating clean projects (Gin: 17 of 22) | `cap_ci_hygiene`: best-practice notes under `.github/` capped at low (script injection in workflows is untouched) |
| 368 of Django's 445 performance findings in tests | `drop_test_performance` |
| Django's "high" Bandit hits that were benign (right-to-left marks, MD5/SHA1 for cache keys) | `soften_bandit_false_alarms`: capped at low unless the line is about a password, secret, token or key |
| Score of 0 for Django exactly as for vulnerable apps | `scoring/calculator.py`: `100 x exp(-penalty / (files x 0.8))`, size floored at 50 files; constants fitted to these eight repos |
| Request values reaching sinks through a variable | six taint rules (PHP: file inclusion, XSS, command injection; JS/TS: XSS, command injection, path traversal), with casts, escaping functions, Express `{root}` and PHP `in_array`/`is_numeric` guards ending the flow |
| CI sent a PR's code to Groq whenever the key was set | audit step runs `--static-only` and no longer gets the key; also pip-audit (pinned, informational), SARIF upload on pushes, Dependabot |

**Final before/after on `c6cd1c3`** (the old-score column uses the old formula; "before" for Gin, petclinic, DVWA and Django was taken partway through the work, so their improvement is understated):

| Repo | Findings | High + crit | Medium | Score (old to new) |
|---|---|---|---|---|
| flask | 39 to 36 | 6 to 1 | 8 to 9 | 0.0 to 72.8 |
| express | 88 to 42 | 25 to 0 | 48 to 25 | 0.0 to 70.1 |
| gin | 22 to 22 | 0 to 0 | 20 to 3 | 25.0 to 69.8 |
| django | 2,521 to 2,152 | 11 to 5 | 614 to 544 | 0.0 to 47.0 |
| spring-petclinic | 11 to 11 | 1 to 1 | 10 to 3 | 54.5 to 73.5 |
| NodeGoat | 51 to 37 | 13 to 8 | 35 to 21 | 0.0 to 11.1 |
| DVWA | 65 to 69 | 28 to 28 | 35 to 26 | 0.0 to 15.5 |
| pygoat | 236 to 211 | 65 to 63 | 92 to 63 | 0.0 to 8.7 |

Not re-triaged finding by finding: these counts show less noise, not a measured precision.

## 3. Open items, in suggested order

1. **Check the CI run on `main`** (https://github.com/KULLOLLITARUN/aegisscan/actions): the audit summary (base ref, files analysed, findings, gate line), the pip-audit step, and the SARIF upload (code scanning may need enabling in the repo settings). Job logs need a login; the unauthenticated REST endpoint `/repos/<owner>/<repo>/actions/runs/<id>/jobs` shows each step's conclusion.
2. **Cross-file analysis is the real remaining recall gap.** Semgrep OSS follows taint inside one file only, so DVWA's XSS and file inclusion (the value is assigned in one file and used in another) are still missed. OpenGrep 2.0 was tried and did not help (section 5); Joern is the heavier option, or an LLM pass over the including file.
3. **LLM pass not re-measured.** All real-repository scans were static-only. The LLM would be the only tool to catch file upload, weak session ids and crypto design flaws. A live run sends code to Groq: ask first, use a small repository.
4. **Known weaknesses:** the benchmark is self-authored and the ECE/score constants are fitted to it and to the eight repos; the score uses files analysed as size (lines of code would be better) and old stored scores are not comparable with new ones; prompt-injection defence is untested live; taint rules do not see custom validation (allow-lists other than `in_array`, custom sanitisers) and follow taint through method calls such as `.slice()`; Django still has 544 medium findings, mostly notes in tests at reduced weight; no UI tests.
5. **Housekeeping:** delete the old local branches (local only). Contributors box on GitHub may still list "Claude" (sidebar cache; a GitHub Support request can purge old SHAs if it persists).
6. **Tool ideas** (vetting rules in section 4): pip-audit as a scanner feature (today only a CI step), a `dependencies:high` gate spec, Hadolint, promptfoo or garak for prompt-injection tests, GuardDog, Ruff `S`/`PERF`, zizmor in CI. Trivy and KICS are excluded.

## 4. Decisions already made — do not reopen without asking

- **No Render deployment.** `render.yaml`, the Dockerfile and `Plans/RENDER_DEPLOY_CHECKLIST.md` stay untouched. Hosted mode and the Cloudflare tunnel launcher were not ruled out.
- **Never add `Co-Authored-By: Claude` or any Claude attribution** to commits or PR text (saved in memory too). This overrides any tool reminder to add one.
- **Only vetted open-source tools.** Checklist: OSI licence, reputable maintainer, verifiable releases (attestation or pinned hash), a search for security incidents, no execution of scanned code, note what data leaves the machine; pin by exact version and hash (commit SHA for Actions). Ask before installing anything.
- `exclude_dirs` applies to every tool.
- **Bundled rules:** direct uses were the original rule; the user then asked for taint rules, so those exist too, but only intra-file, with guarded safe twins in the benchmark.
- Non-production paths are demoted, not hidden: findings stay visible with an explanatory note.

## 5. OpenGrep experiment (done 2026-11-24): not adopted

**Vetting.** OpenGrep 2.0.0 (GitHub release `opengrep/opengrep`, 2026-11-13): LGPL-2.1, GitHub organisation with about 3.4k stars, created Dec 2024, Aikido-backed. Release assets carry a SHA-256 digest and a Sigstore `.sig` + `.cert`. Checked: the downloaded Windows zip matches GitHub's digest; the certificate identity is `opengrep/opengrep` `rolling-release.yml` on `main` via GitHub Actions; the signature verifies against the certificate's key (`openssl`; the chain to the Sigstore root and the transparency log were not checked, no `cosign` installed). **Never `pip install opengrep`**: malicious or hijacked PyPI packages with that name were reported. It has no `--metrics` flag and no telemetry switch. Binary kept only in the session scratchpad (`og_bin/`), nothing installed, no project file changed.

**Results** (the runner was patched in memory to use it and drop `--metrics=off`; `og_run.py`, `og_interfile.py` in the scratchpad):
- Benchmark (static-only, registry packs plus bundled rules): precision 90.48% (Semgrep 90.25%), recall 100% / 95.68% (same), ECE 0.123 (0.122). Adding `--taint-intrafile` changed nothing. It reports fewer Semgrep-side findings (127 against 152) for the same recall; not investigated.
- On DVWA it finds 5 more taint hits than the current Semgrep setup (12 against 7): 2 are the `exec/impossible.php` false positives that Semgrep's `is_numeric` guard handling removes (OpenGrep treats that by-side-effect sanitiser differently), 3 are `dvwaPage.inc.php` echoes of page config (`$pPage['title']`, `$menuHtml`), very likely not request-controlled. `--enable-interfile` (cross-file taint) gave the same 12 and did **not** find DVWA's cross-file XSS or file inclusion; those flows go through `require_once` of a run-time-built path, which a call graph does not resolve. Express and NodeGoat: identical taint hits with every mode.
- It is much faster on the taint rules alone (about 0.6 s against 4 s).

**Verdict:** no accuracy gain, a few more false positives, a 44 MB binary to pin and a runner change (`--metrics`). Not worth adopting now. Revisit only for speed, or if rules written for cross-file flows through plain function calls show a gain on a repository that has them.

## 6. How this user likes to work

- Asks for a change, reviews the summary, then says "commit and push it" (and, this session, "push all to main"). **Do not commit or push before being told**, and run the full tests before pushing. Check CI after a push.
- Force-push, deleting remote branches, installing third-party tools and anything touching credentials need an explicit go-ahead.
- Prefers honest reporting: say what was measured, what was only inferred and what could not be checked. Say plainly when a gain is small.
- No `gh` CLI: the user opens PRs from a pre-filled compare URL.

## 7. Environment quirks

- Windows 11; use the venv: `.venv\Scripts\python.exe`. Tests: `python -m pytest -q -p no:cacheprovider` (about 4-5 min now); with CI's coverage gate add `--cov=scanner --cov-fail-under=75`. Lint: `python -m ruff check .`, types: `python -m mypy`.
- Semgrep needs network (registry packs). It also silently drops a whole rule file that is invalid YAML (a badly quoted `{root: ...}` once removed every JS rule): after editing a `rules/*.yml` run `semgrep --validate --config <file>`; `tests/test_v30_rule_confidence.py` does this too.
- **Shell quirk:** Git Bash heredocs and `python -c` strip or mangle backslashes and quotes (a `\\u` regex lost a backslash). Write files with the Write/Edit tools, not shell heredocs, whenever they contain backslashes or many quotes. Many source files use CRLF.
- A path containing `&` breaks `npm run` under cmd.exe: call the tools through node (`node node_modules/vite/bin/vite.js build`).
- WSL is broken here, so Linux-only failures show up only in CI. The dev box has no Gitleaks binary (CI has 8.21.2).
- Long commands may be auto-backgrounded; their output lands in the task output file. A monitor watching for the word "passed" can fire on ruff's "All checks passed!": wait for the pytest summary line instead.
- Real-repository scan clones and result JSON from this round are in the session scratchpad and may be gone.

## 8. First things to do

```
git fetch && git status -sb              # main should be at or after c6cd1c3
python -m pytest -q -p no:cacheprovider  # expect 925 passed, 3 skipped
```
Then check the CI run (item 1) and ask which item to start with.
