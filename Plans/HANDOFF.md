# AegisScan — handoff for the next session

_Updated 2026-11-25 after the real-repository round and two live LLM runs. Read this first, then `Plans/REMAINING_ISSUES_AND_TESTING.md` (the detailed issue list and fixed-items table) and `HOW_IT_WORKS.md`._

## 0. WORK IN PROGRESS (2026-11-25): UI overhaul, uncommitted

About 42 files are changed or new in the working tree and **not committed**. `main` on GitHub is `ca9f44b`: it holds only the two live-scan commits below (`35f3eef`, `ca9f44b`), built on `92ddb35` with just those lines staged from the shared files. Do not discard the rest. The user asked to stop and continue in a new session.

**Built (all seven planned steps):**
1. History page redesigned (trend chart in `ui/src/components/history/TrendChart.jsx`, clickable rows), a real **Cancel scan** (server: `ScanCancelled`, a BaseException raised from the progress callback once the SSE client is gone; stops at the next progress point), `recharts` removed, the legacy CSS alias layer and `index.css` classes removed.
2. Colours: contrast measured from the OKLCH tokens (script was in the scratchpad: OKLCH to sRGB, WCAG ratio); four text tokens fixed (Day sev-high/medium/info, Night muted-2), all text now >= 4.5:1 in both themes. New `--status-*` score scale (`ui/src/lib/score.js`), categories as icon tags (`CategoryTag.jsx`, no colour: colour means severity), `prefers-contrast` and `forced-colors` support, the HTML report and `score_color` on the Night palette.
3. Export (`POST /api/export?format=html|sarif|json`, `ExportMenu.jsx`), down-weighting badges parsed from the explanation prefixes (`ui/src/lib/notes.js`, `NoteBadges.jsx`), "hide down-weighted" and tool filters, toasts (`ToastContext.jsx`).
4. Motion: score count-up (`ScoreNumber.jsx`), pin landing overshoot, View Transitions for pages and theme (`ui/src/lib/transition.js`), row stagger, canvas sway as a 14 s intro and no style writes when idle.
5. Persistence: `scanner/storage/results.py` keeps the newest 30 local web results; `GET /api/last`, `GET /api/scan/<id>`, `has_result` in `/api/history`; restore on reload, open from History, new/fixed against the previous kept scan (`ui/src/lib/findingKey.js`, `useLocalState.js`).
6. Triage: `scanner/storage/triage.py`, `GET/POST /api/triage`, "Mark false positive" / "Accept risk" / "Reopen" in the evidence view, "hide triaged" filters. UI-only: it does not change what the scanner reports (CI suppression is still `--save-baseline`).
7. Tests: `tests/test_v33_ui_backend.py` (24), `ui/tests/lib.test.mjs` (9, Node's built-in runner with a small resolver hook, `npm test`), CI step "Test UI logic".

**Found and fixed on the way:** SARIF export crashed on a relative target (hosted results use a label); `save_result` could fail a scan on an unexpected result shape (now fully guarded); four layout bugs seen in screenshots (location column breaking mid-number, "Secret scan" wrapping, oversized severity select, score chip hidden under reduced motion).

**Verified:** ruff and mypy clean; UI build and oxlint clean (only the existing fast-refresh warnings on context files); the 24 + 9 new tests pass; `test_v13_coverage`, `test_v14_progress`, `test_v4_scoring_html`, `test_v6_ci_privacy` pass. Visual check in headless Edge (Day and Night: Scan, Findings, History) after a static scan of `examples/vulnerable_python`.

**Still to do, in order:**
1. Run the **full** suite once on this code (`python -m pytest -q -p no:cacheprovider > log`, not piped through `tail`, about 5 min). The last full run was stopped at 25% with everything passing so far; an earlier one reached about 90% before the `save_result` fix.
2. If green, commit and push to `main` (the user's chosen workflow; no Claude attribution).
3. Optional: animations were only seen as end states (headless screenshots under reduced motion); open the app in a real browser to see the motion. Not checked: very large results (Django), screen readers.

**Screenshot recipe (no tools installed):** start `python main.py --server --port <free>`, POST a static scan to `/api/scan` (build the JSON in Python: shell quoting of Windows paths breaks), then `msedge.exe --headless=new --disable-gpu --user-data-dir=<temp> --window-size=1440,900 --blink-settings=preferredColorScheme=1|0 --force-prefers-reduced-motion --virtual-time-budget=20000 --screenshot=<file> http://127.0.0.1:<port>/dashboard`. Build output paths with `cygpath -w`, not `"$DIR\\$name"` (the backslash stops variable expansion). Without reduced motion the capture lands mid-animation; without `preferredColorScheme` headless Edge follows the system's dark mode.

**File inventory (26 changed, 17 new; +762 / -623 in the changed files):**

| Area | Changed | New |
|---|---|---|
| Server | `scanner/server/app.py` (cancel, export, kept results, triage, history `has_result`), `scanner/reporting/html_report.py` (Night palette), `scanner/reporting/sarif_report.py` (relative-target fix), `scanner/scoring/calculator.py` (`score_color` status scale) | `scanner/storage/results.py`, `scanner/storage/triage.py` |
| Tests / CI | `tests/test_v4_scoring_html.py` (new colours), `.github/workflows/security-scan.yml` ("Test UI logic" step) | `tests/test_v33_ui_backend.py`, `ui/tests/{lib.test.mjs,register.mjs,resolve.mjs}` |
| UI shell & state | `App.jsx` (ToastProvider), `CommandBar.jsx` (Cancel, Export, theme transition), `RailNav.jsx` (page transitions), `ScanContext.jsx` (cancelScan, local state) | `context/ToastContext.jsx`, `shell/ExportMenu.jsx`, `lib/useLocalState.js`, `lib/transition.js` |
| UI pages & components | `ScansPage.jsx` (rewrite), `FindingsPage.jsx` (filters), `FindingTable.jsx`, `FindingsQueue.jsx`, `Evidence.jsx` (badges, flags, triage, toasts), `ScanCanvas.jsx` (sway intro, idle), `Verdict.jsx` (count-up, status chip, new/fixed) | `ScoreNumber.jsx`, `findings/{CategoryTag,FindingFlags,NoteBadges}.jsx`, `history/TrendChart.jsx` |
| UI libs & styles | `constants.js` (TRIAGE_LABEL), `lib/api.js` (exportResult), `lib/paths.js` (normPath), `styles/tokens.css`, `styles/aegis.css`, `index.css` (legacy removed), `package.json` (test script, no recharts), `package-lock.json` | `lib/{score,notes,findingKey,time}.js` |

**New API (local mode unless noted; all behind the existing Host/Origin gate and, in hosted mode, the token):**
- `POST /api/export?format=html|sarif|json`: body is a ScanResult (validated with the model, at most 32 MB); returns an attachment. Works in hosted mode too.
- `GET /api/last`, `GET /api/scan/<uuid>`: a kept result as JSON, or 404. Ids are checked against `^[0-9a-fA-F-]{8,64}$` before touching the disk.
- `GET /api/triage?target=...`, `POST /api/triage {target, key, status: "false_positive"|"accepted"|null}`.
- `GET /api/history`: rows now carry `has_result`.
- Hosted mode: the kept-result and triage endpoints answer 404; nothing is stored.

**Design decisions made in this round (keep unless the user says otherwise):**
- Colour means severity and score status only; categories get icons. 14 category hues would collide with the severity hues and exceed the 8-hue limit for distinguishable series.
- Status colours are marks next to a label, never text colour (they clear 3:1, not 4.5:1).
- The finding key for new/fixed and triage is relative path + tool + issue type + category, with no line number, so an edit above a finding does not make it "new". Counting is per key (three identical findings, two left: one fixed).
- Kept results: newest 30, stored next to the history database (`%LOCALAPPDATA%\AegisScan\results\`), never in a scanned folder. Triage: `%LOCALAPPDATA%\AegisScan\triage.json`.
- Cancel stops at the next progress point; a long step such as Semgrep finishes first. The UI says so.
- Motion respects reduced motion everywhere (CSS animations and delays to 0, no View Transitions, score shown at once, no replay autoplay, no sway).
- UI tests use Node's built-in runner, so nothing was installed; a browser test (Playwright) would be an install and needs the user's OK.

**Known limits left:** long Semgrep messages used as issue titles wrap to two or three lines (content, not layout); Files page still lists only files with findings; the screenshots show end states only.

**Live scan view (2026-11-25, committed and pushed as `35f3eef` and `ca9f44b`).** While a scan runs the canvas draws the real file list and fills in findings as each static tool finishes.
- New optional callbacks on `main.run`: `on_files(list[{"path", "lines"}])`, called once after classification with the analysable files (path relative to the target, posix); `on_findings(tool, list[{"path", "worst", "count"}])`, called after each static tool with that tool's raw findings grouped by file. `run_all_tools` takes `on_findings(tool, list[Finding])` and calls it only for tools that found something. Callers that pass neither behave as before, so the existing tests that stub `run_all_tools` still work. Callback errors are swallowed.
- New SSE events on `/api/scan/stream`, local and hosted: `files` = `{files: [{path, lines}], total}` (at most 5000 files, `total` is the true count) and `preview` = `{tool, files: [{path, worst, count}]}`. Paths are relative, so nothing needs scrubbing in hosted mode. The final `complete` event is unchanged.
- **Preview counts are preliminary:** they are raw tool output before deduplication, context weighting and suppression, so the final result can be lower (a `scanner` run showed 29 live and 25 final). The UI labels them "preliminary" everywhere.
- UI: `ScanContext` keeps `liveFiles` and `liveHits` (reset per scan; `lib/liveHits.js` `mergePreview` adds counts per file and keeps the worst severity); `lib/scene.js` `buildLiveScene` lays out one small tile per file sorted by path, sampled to 240 tiles with `hiddenFiles` counting the rest; `ScanCanvas` shows them during a scan (tile tinted with its worst severity plus one ring when a preview finding arrives; the old result's notes are hidden while live); `Timeline` shows "N found so far, preliminary" under the clock.
- **Honest limits:** the scanner reports progress per tool, not per file, so which tile lights when the sweep passes is illustrative (the canvas says so). A preview finding in a file that is not drawn (over 240 files) counts in the total but has no tile. The design preview with the belt, gate and falling blocks is `Plans/live-scan-preview.html`; it was not built into the real UI because there are no per-file events to drive it.
- Tests: `tests/test_v14_progress.py` (4 new), `ui/tests/lib.test.mjs` (4 new, in the still-uncommitted tests folder). The full Python suite last ran 960 passed, 3 skipped, 1 failed: `test_v31_real_repo_noise.py::test_mongo_where_rule` timed out in a Semgrep subprocess on this machine (cause not investigated).
- Possible next steps: pick up preview findings for files that are not drawn; per-tool gate label; a real per-file event stream would need the static tools to report per file.

## 1. Snapshot

**What it is:** a hybrid security + optimization scanner. Bandit, Semgrep, Gitleaks, OSV-Scanner and a built-in optimizer run first; a Groq LLM pass reasons over the code and the static findings; results go to CLI, HTML, JSON and SARIF, a React web UI (`ui/`), and a CI gate (`--fail-on security:high`).

**Repo:** `github.com/KULLOLLITARUN/aegisscan`, branch `main` (the only remote branch). Local working copy: `D:\AI_Projects\AI-Driven_Workspace_Security_&_Optimization_Scanner`.

**State at handoff**
- `main` at `99cd872`; everything is merged and pushed, and every merged branch is deleted (local has only `main`; the only other remote branch is Dependabot's). Open on GitHub: five Dependabot npm PRs (#4 to #8) from before the update grouping; the user closes them with `@dependabot close`, after which one grouped weekly PR per ecosystem replaces them.
- Tests: 935 passed, 3 skipped. ruff and mypy clean. Not yet seen: the CI run on `main` (first run of the new workflow, see item 1 below).
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

## 2b. Live LLM runs (2026-11-24/25): Gin and NodeGoat

Both ran with the default selective trigger, `--privacy standard`, model `openai/gpt-oss-20b` with Groq failing over to `gpt-oss-120b` and `qwen3.8-27b`. Public code only, with the user's go-ahead each time. Cost: Gin 10 requests / 74 s / 5 rate-limit failovers; NodeGoat 41 requests / 259 s / 43 failovers and 16 empty responses (Groq's free tier throttles hard; expect slow runs).

| Repo | Static-only | With the LLM, before the fixes | What the LLM added |
|---|---|---|---|
| Gin (clean) | 22 findings, score 69.8 | 37 findings, score 27.1 | nothing real: re-reported the workflow notes as `access_control`/`secrets` at confidence 1.00 (seven "high"), plus a high-rated `unsafe` conversion that is deliberate |
| NodeGoat (vulnerable) | 37 findings, score 11.1 | 67 findings, score 1.8 | 4 real, design-level findings static rules cannot express: session fixation (`session.js:116`, high), XSS through the fetched body (`research.js:24`), the `/allocations/:userId` access-control gap (`index.js:63`), user enumeration (`session.js:78`, location points at a comment); about 16 more were noise |

Verdict: useful as an opt-in second opinion on code with design-level bugs, net-negative on clean code. Fixes on `main` (all post-processing, replayed offline on the saved runs, not re-run live; the model's output varies between runs):

- `cap_ci_hygiene` also caps LLM findings under `.github/` in any non-injection category at low severity and 0.5 confidence.
- `deduplicator._drop_llm_echoes`: an LLM finding that re-labels a static `best_practices` note on the same lines is dropped, unless its category is injection, xss, deserialization or path_traversal.
- `deduplicator._bound_llm_severity`: when a more confident LLM finding wins a cluster, it keeps its text and confidence but not a higher severity than the static finding (same high-impact exemption).
- `context.soften_llm_noise`: LLM best-practice or performance findings whose short title is a code-quality remark ("missing error handling", "undefined variable", "radix", "zero-based"...), and any LLM finding in developer tooling (`artifacts/`, `scripts/`, `tools/`, `tasks/`, `build/`, `ci/`, `Gruntfile.js`, `gulpfile.js`), are capped at low and 0.5. Heuristic, tuned on these two repositories.
- Replay: Gin with the LLM scores 67.8 (static-only 69.8) with no high finding; on NodeGoat 18 findings were capped and the real ones kept their severity.

Still missed by the LLM on NodeGoat: the `$where` NoSQL injection (the static rule catches it), ReDoS in `profile.js` (neither tool reports it, unconfirmed), CSRF. Still noisy: the `tutorial.js` "arbitrary file read" (the page name comes from a fixed list) and an `eval` example in a tutorial HTML page.

## 3. Open items, in suggested order

1. **Check the CI run on `main`** (https://github.com/KULLOLLITARUN/aegisscan/actions): the audit summary (base ref, files analysed, findings, gate line), the pip-audit step, and the SARIF upload (code scanning may need enabling in the repo settings). Job logs need a login; the unauthenticated REST endpoint `/repos/<owner>/<repo>/actions/runs/<id>/jobs` shows each step's conclusion.
2. **Cross-file analysis is the real remaining recall gap.** Semgrep OSS follows taint inside one file only, so DVWA's XSS and file inclusion (the value is assigned in one file and used in another) are still missed. OpenGrep 2.0 was tried and did not help (section 5); Joern is the heavier option, or an LLM pass over the including file.
3. **LLM pass: measured on two repositories only** (section 2b). Not yet tried: DVWA (file upload, weak session ids and crypto design flaws are the kind of thing only the LLM can catch there), `--deep`, or a larger repository. A live run sends code to Groq: ask first, use a small public repository, and re-run the saved-run replay (rebuild the pre-dedup input from the static-only scan plus the LLM findings) rather than paying for a second run when only post-processing changed.
4. **Known weaknesses:** the benchmark is self-authored and the ECE/score constants are fitted to it and to the eight repos; the score uses files analysed as size (lines of code would be better) and old stored scores are not comparable with new ones; prompt-injection defence is untested live; taint rules do not see custom validation (allow-lists other than `in_array`, custom sanitisers) and follow taint through method calls such as `.slice()`; Django still has 544 medium findings, mostly notes in tests at reduced weight; no UI tests.
5. **Housekeeping:** close Dependabot PRs #4 to #8 (the user does this on GitHub). Contributors box on GitHub may still list "Claude" (sidebar cache; a GitHub Support request can purge old SHAs if it persists).
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

- Asks for a change, reviews the summary, then says "push to main" (or "push to main once tests pass"). Late in the 2026-11-25 session they said "don't push as PR": the default is now a direct push to `main`, not a branch and pull request. **Do not commit or push before being told**, and run the full tests before pushing. Check CI after a push.
- Run `git branch -d` on merged branches only after checking they are merged into `main`; the user asked for merged branches to be deleted and a clean local repo.
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
git fetch && git status -sb              # main should be at or after 99cd872
python -m pytest -q -p no:cacheprovider  # expect 935 passed, 3 skipped
```
Then check the CI run (item 1) and ask which item to start with.
