# AegisScan — UI Plan

**Status:** Design reference. This describes the target UI once the backend milestones that feed it exist (primarily V4 Developer Experience, with pieces from V3 Baseline and V6 CI). Do not start building this before `AEGISSCAN_PLAN.md` V0–V3 are done — there is no data to render yet.

**Companion doc:** `AEGISSCAN_PLAN.md` (backend architecture + versioned roadmap). This file must stay consistent with that one — every field shown here should trace back to a model or feature defined there.

---

## 1. Design goals

- Clarity first
- Fast triage of critical issues
- Actionable insights
- Developer friendly
- Works in CLI and Web/HTML

---

## 2. Visual system

### Color / severity map

| Severity | Color |
|---|---|
| Critical | `#FF404D` |
| High | `#FF9F43` |
| Medium | `#FFD166` |
| Low | `#6BCB77` |
| Info | `#4D96FF` |

### Typography

- Font: Inter / JetBrains Mono (code)
- Base scale: 12px

### Theme

- Dark theme default (dev-tool convention, high contrast for severity colors)

---

## 3. Screens

### 3.1 Dashboard

Left nav: Dashboard, Findings, Files, Rules & Tools, Scans, Baseline, Reports, Settings.

Top bar: workspace selector, scan ID + timestamp, scan status badge, Export, Re-scan.

**Summary cards** (severity counts, each with a "since last scan" delta and a sparkline):
- Critical Issues
- High Issues
- Medium Issues
- Low Issues
- Info

**Risk Scores** — two independent radial scores, per the backend's separate scoring model:
- Security Score (e.g. 62/100 — "High Risk")
- Optimization Score (e.g. 74/100 — "Medium Risk")

> These map directly to `ScanResult.security_score` / `ScanResult.optimization_score` (see plan §31–32). Do not blend them into one number — that was an explicit backend decision.

**Findings by Category** — donut chart (Injection, Secrets, Access Control, Crypto, Performance, Best Practices), each slice clickable to filter the findings list.

**Scan Summary** — files scanned, lines of code, languages detected, scan duration, static tools run, LLM provider/model used, privacy mode active.

> Static Tools and LLM Provider are shown as distinct rows — this reflects the static-first architecture (plan §2 rule 1) and should not be merged into a single "analysis engine" line.

**Top 5 Critical/High Findings** — table (ID, Title, Category, File, Line, Severity, Confidence) with a link to the full findings list.

---

### 3.2 Findings List

- Search bar + filters: Severity, Category, Status, plus an "Advanced Filters" panel.
- Table columns: ID, Title, Category, File, Line, Severity, Confidence.
- Pagination (7 of 187 results shown, page controls).
- Row click → Finding Detail panel.

---

### 3.3 Files View

- Left: file tree (respects the same ignore rules as the crawler — `node_modules`, `.git`, etc. should never appear here, consistent with plan §9).
- Middle: findings-in-this-file list for the selected file, each showing ID / title / line.
- Right: File Stats — language, lines of code, function count, class count, average complexity.

---

### 3.4 Finding Detail

This is the most important screen — it's the direct UI representation of the `Finding` model (plan §7 core model).

**Header:** Finding ID, title, severity badge, confidence score, Prev/Next navigation, Back to Findings.

**Tabs:** Overview, Evidence, Explanation, Suggested Fix, History.

**Overview panel:**
| Field | Source (Finding model field) |
|---|---|
| Category | `category` |
| Rule Source | `rule_source` (e.g. "semgrep", "llm") |
| Provider | `provider` + `model` (e.g. "Groq (Llama 3.3 70B)") |
| File | `file_path` |
| Line Range | `line_start`–`line_end` |
| First Seen | derived from scan history, not a raw Finding field — needs a small lookup against baseline/history data |

**Description** — `explanation` field, plain text.

**Evidence (Code)** — syntax-highlighted snippet from `evidence`, with the flagged line(s) visually marked.

**Suggested Fix (AI)** — `corrected_code`, shown as a diff-style before/after against the evidence block.

**Explanation** — `impact` + remediation guidance, plain text below the fix.

> Note: showing both Rule Source (e.g. "Semgrep") and Provider (e.g. "Groq") on the same finding only makes sense once V3 correlation exists — a finding that started as a static detection and was enriched by the LLM should show both, per the `rule_source: "correlated"` case in plan §3.

---

### 3.5 Scan History

- Table: Scan ID, Date, Status (Completed / Failed / In Progress), Files, Findings, Score (Security / Optimization).
- A "Failed" status row must be a real, representable state — the UI should not assume every scan succeeds. This maps to the plan's graceful-degradation rule (§2 rule 6): a scan that hit a provider outage should still appear in history, clearly marked, with whatever partial/static-only results it produced.
- "View All Scans" link to full paginated history.

---

### 3.6 Mobile View

Condensed version of Dashboard and Findings:
- Summary cards in a 2-column grid instead of a row.
- Findings list collapses file/line into the card body instead of table columns.
- Same severity color system, same bottom nav (Dashboard, Findings, Files, More).

---

## 4. Interactive elements checklist

- Search
- Filter (severity, category, status)
- Sort
- Expand/Collapse (tree views, code blocks)
- Export
- Pagination
- Tabs
- Code blocks (syntax highlighted, diff-capable for Suggested Fix)

---

## 5. Export formats

| Format | Purpose |
|---|---|
| JSON | Automation, `aegisscan-results.json` (plan §35) |
| HTML | Human-readable report (plan §36) |
| **SARIF** | GitHub code scanning / PR inline annotations — **not yet in the backend plan; add to `AEGISSCAN_PLAN.md` §4 V6 and §5 CLI surface as `--format sarif`.** This is the actual mechanism GitHub Actions needs to post findings inline on a PR diff, so it's a requirement for V6, not optional polish. |

---

## 6. Known inconsistencies to resolve before implementation

1. **Confidence display format.** This wireframe shows confidence as a decimal (`0.89`). The CLI mockup in `AEGISSCAN_PLAN.md` §33 shows it as a percentage (`96%`). Pick one and use it consistently across CLI, HTML, and this UI — recommend percentage for human-facing surfaces (CLI/HTML/UI) and keep the raw `float 0.0–1.0` only in the JSON/`Finding` model itself.
2. **"Rules & Tools" and "Baseline" nav items** have no wireframe yet. These imply real functionality — enabling/disabling specific Semgrep rules, viewing and editing baseline-suppressed findings. Design these when V1 (static tools) and V3 (baseline) land, not before.
3. **"First Seen" field** on Finding Detail requires a small history/dedup lookup that isn't explicitly modeled yet — needs a `first_seen_scan_id` (or similar) added to `Finding` or tracked separately in scan history once V6 historical tracking exists.

---

## 7. Future enhancements (post-V1 of the UI, i.e. not in the first build)

- Hotspot view (risk heatmap across files)
- Code graph (callers/callees) — visual counterpart to the backend's Context Builder (plan §14 / V3)
- Trend charts over time (requires V6 historical scan data)
- Baseline diff view (what changed in suppressed findings between scans)
- PR inline annotations (requires SARIF export, see §5 above)

---

## 8. Operating rule

This UI is a **target design**, matched against the backend `Finding`/`ScanResult` models as they exist today. If the backend models change (new fields, renamed fields, new `rule_source` values), this doc needs a pass to stay in sync — treat drift between the two docs as a bug.

Do not begin implementing any screen here until the backend milestone that produces its data exists:
- Dashboard, Findings List, Finding Detail → need V1–V3 (static + LLM findings, aggregation)
- Risk Scores → need V4 (scoring is explicitly deferred until real findings exist to calibrate against)
- Scan History → needs V6 (historical tracking)
- SARIF export / PR annotations → need V6 (CI integration)
