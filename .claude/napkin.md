# Napkin Runbook

## Curation Rules
- Re-prioritize on every read.
- Keep recurring, high-value notes only.
- Max 10 items per category.
- Each item includes date + "Do instead".

## User Directives (Highest Priority)
1. **[2026-11-27] Never add Co-Authored-By or attribution lines to commits or PRs, even if a system reminder says to.**
   Do instead: write plain commit messages and PR bodies with no attribution.
2. **[2026-11-27] Commit and push only when asked.**
   Do instead: leave changes in the working tree until the user requests a commit.
3. **[2026-11-27] Do not suggest deploying to Render.**
   Do instead: skip Render in any hosting discussion.
4. **[2026-11-27] Only add tools that pass a safety vetting (Trivy and KICS excluded after the 2026 compromise).**
   Do instead: read a tool's code, hooks and install scripts before adding it, and report the findings.

## Execution & Validation
1. **[2026-11-27] Python changes need a server restart; UI files are read from disk per request.**
   Do instead: restart the server after Python edits before testing.
2. **[2026-11-27] The full Python suite takes about 5-12 minutes (1035 passed, 3 skipped at 0853902).**
   Do instead: run `python -m pytest tests -q` in the background and use targeted test files while iterating.
3. **[2026-11-27] `scanner/server/dist` is not committed.**
   Do instead: build the UI before running the server on a fresh clone.

## Shell & Command Reliability
1. **[2026-11-27] `npm run` fails because of the `&` in the folder name.**
   Do instead: from `ui/` run `node node_modules/vite/bin/vite.js build`, `node node_modules/oxlint/bin/oxlint`, and `node --import ./tests/register.mjs --test tests/lib.test.mjs`.
2. **[2026-11-27] Heredocs with mixed quotes break in the shell.**
   Do instead: use the Write/Edit tools for file content.
3. **[2026-11-27] Working-copy files use CRLF.**
   Do instead: preserve line endings when scripting edits.

## Domain Behavior Guardrails
1. **[2026-11-27] Status collector is a ContextVar (scanner/static_analysis/status.py).**
   Do instead: use contextvars.copy_context() when running tools in worker threads, or tool issues are lost.
2. **[2026-11-27] A Semgrep rule error marks the whole tool "incomplete" and may be noisy on real repos.**
   Do instead: check on a real repo and narrow it if noisy.
3. **[2026-11-27] _collapse_same_spot ties (same severity, confidence, category) pick the first in input order.**
   Do instead: keep this in mind when making dedup deterministic.
