"""
HTML Report Generator — produces a self-contained HTML file from a ScanResult.

Design language: dark "Midnight Obsidian" theme matching AEGISSCAN_UI_PLAN.md.
Output: single .html file with all CSS and JS inlined (no external CDN deps).

Features:
  - Security + optimization score gauges (SVG arc)
  - Findings table with severity badges, sortable by column
  - Expandable rows showing evidence + explanation + suggested fix
  - Intelligence layer summary (dedup, correlation, baseline)
  - Tool attribution per finding
  - Scan metadata header card
"""
from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path

from scanner.models.finding import Finding, Severity
from scanner.models.scan import ScanResult
from scanner.scoring.calculator import score_color, score_label

# ---------------------------------------------------------------------------
# Colour constants (Midnight Obsidian palette)
# ---------------------------------------------------------------------------

_SEV_COLORS: dict[Severity, tuple[str, str]] = {
    # (background, text)
    Severity.CRITICAL: ("#ff4444", "#fff"),
    Severity.HIGH:     ("#ff6b35", "#fff"),
    Severity.MEDIUM:   ("#f0b429", "#0d1117"),
    Severity.LOW:      ("#79c0ff", "#0d1117"),
    Severity.INFO:     ("#8b949e", "#fff"),
}

_SEV_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH:     "HIGH",
    Severity.MEDIUM:   "MEDIUM",
    Severity.LOW:      "LOW",
    Severity.INFO:     "INFO",
}

_SOURCE_COLORS: dict[str, str] = {
    "bandit":   "#f0b429",
    "semgrep":  "#58a6ff",
    "gitleaks": "#ff4444",
    "llm":      "#a371f7",
    "aegis-opt": "#3fb950",
}


def _badge(text: str, bg: str, fg: str = "#fff") -> str:
    return (
        f'<span style="background:{bg};color:{fg};padding:2px 8px;'
        f'border-radius:4px;font-size:0.75rem;font-weight:700;'
        f'white-space:nowrap">{html.escape(text)}</span>'
    )


def _sev_badge(sev: Severity) -> str:
    bg, fg = _SEV_COLORS[sev]
    return _badge(_SEV_LABEL[sev], bg, fg)


def _source_badge(source: str) -> str:
    bg = _SOURCE_COLORS.get(source, "#58a6ff")
    return _badge(source.upper(), bg)


def _score_gauge(score: float, label: str, subtitle: str) -> str:
    """SVG arc gauge for a score value."""
    colour = score_color(score)
    rating = score_label(score)
    # Arc: radius=54, circumference=339.3, offset represents (100-score)/100 * circ
    circ = 339.3
    offset = circ * (1 - score / 100)
    return f"""
    <div class="gauge-card">
      <svg viewBox="0 0 120 70" width="200" height="120">
        <circle cx="60" cy="60" r="54" fill="none" stroke="#21262d" stroke-width="10"
                stroke-dasharray="339.3" stroke-dashoffset="0"
                stroke-linecap="round" transform="rotate(-180 60 60)"/>
        <circle cx="60" cy="60" r="54" fill="none" stroke="{colour}" stroke-width="10"
                stroke-dasharray="{circ:.1f}" stroke-dashoffset="{offset:.1f}"
                stroke-linecap="round" transform="rotate(-180 60 60)"
                style="transition:stroke-dashoffset 1s ease"/>
        <text x="60" y="52" text-anchor="middle" fill="{colour}"
              font-size="20" font-weight="700" font-family="Inter,system-ui,sans-serif">
          {score:.0f}
        </text>
        <text x="60" y="65" text-anchor="middle" fill="#8b949e"
              font-size="8" font-family="Inter,system-ui,sans-serif">
          {html.escape(rating)}
        </text>
      </svg>
      <div class="gauge-label">{html.escape(label)}</div>
      <div class="gauge-sub">{html.escape(subtitle)}</div>
    </div>"""


def _finding_row(f: Finding, idx: int) -> str:
    sev_bg, sev_fg = _SEV_COLORS[f.severity]
    detail_id = f"detail-{idx}"
    conf_pct = f"{f.confidence * 100:.0f}%"

    evidence_html = ""
    if f.evidence:
        evidence_html = f"""
        <div class="detail-section">
          <div class="detail-label">Evidence</div>
          <pre class="code-block">{html.escape(f.evidence)}</pre>
        </div>"""

    explanation_html = ""
    if f.explanation:
        explanation_html = f"""
        <div class="detail-section">
          <div class="detail-label">Explanation</div>
          <div class="detail-text">{html.escape(f.explanation)}</div>
        </div>"""

    fix_html = ""
    if f.suggested_fix:
        fix_html = f"""
        <div class="detail-section">
          <div class="detail-label">Suggested Fix</div>
          <div class="detail-text fix-text">{html.escape(f.suggested_fix)}</div>
        </div>"""

    patch_html = ""
    if f.fix_patch:
        patch_html = f"""
        <div class="detail-section">
          <div class="detail-label">AI Unified Diff Patch</div>
          <pre class="evidence-block" style="border-left:3px solid #238636;color:#e6edf3"><code>{html.escape(f.fix_patch)}</code></pre>
        </div>"""

    source_color = _SOURCE_COLORS.get(f.rule_source, "#58a6ff")

    return f"""
    <tr class="finding-row" onclick="toggleDetail('{detail_id}')" style="cursor:pointer">
      <td><span class="sev-badge" style="background:{sev_bg};color:{sev_fg}">{_SEV_LABEL[f.severity]}</span></td>
      <td><span class="conf-pill">{conf_pct}</span></td>
      <td><span class="source-badge" style="border-color:{source_color};color:{source_color}">{html.escape(f.rule_source.upper())}</span></td>
      <td class="file-cell">{html.escape(f.file_path.name)}<span class="line-num">:{f.line_start}</span></td>
      <td class="issue-cell">{html.escape(f.issue_type)}</td>
      <td class="cat-cell"><span class="cat-tag">{html.escape(f.category)}</span></td>
      <td class="expand-icon">▸</td>
    </tr>
    <tr id="{detail_id}" class="detail-row" style="display:none">
      <td colspan="7">
        <div class="detail-content">
          {evidence_html}
          {explanation_html}
          {fix_html}
          {patch_html}
        </div>
      </td>
    </tr>"""


def generate_html(result: ScanResult, output_path: Path) -> None:
    """Render *result* to a self-contained HTML file at *output_path*."""

    sec_score  = result.security_score     or 0.0
    opt_score  = result.optimization_score or 0.0

    findings_by_sev: dict[Severity, list[Finding]] = {}
    for sev in Severity:
        findings_by_sev[sev] = [f for f in result.findings if f.severity == sev]

    rows_html = "\n".join(
        _finding_row(f, idx)
        for idx, f in enumerate(
            sorted(result.findings, key=lambda f: (list(Severity).index(f.severity), f.file_path.name, f.line_start))
        )
    )

    static_count = sum(1 for f in result.findings if f.rule_source != "llm")
    llm_count    = sum(1 for f in result.findings if f.rule_source == "llm")

    tools_str = ", ".join(result.static_tools_run) or "none"
    llm_str   = f"{result.llm_model or 'n/a'} via {result.llm_provider}" if result.llm_provider else "not configured"

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    history_card_html = ""
    try:
        from scanner.storage.history import ScanHistoryDB
        db_file = result.target_path / ".aegisscan_history.db"
        if db_file.exists():
            db = ScanHistoryDB(db_path=db_file)
            history = db.get_history(limit=5)
            if len(history) > 0:
                history_items = "".join(
                    f'<div class="intel-item"><div class="intel-value">{h["security_score"]:.1f}</div>'
                    f'<div class="intel-label">{str(h["timestamp"])[:10]} ({h["total_findings"]} issues)</div></div>'
                    for h in reversed(history)
                )
                history_card_html = (
                    f'<div class="intel-card">'
                    f'<span class="intel-title">V9 Security Score History (SQLite)</span>'
                    f'{history_items}</div>'
                )
    except Exception:
        history_card_html = ""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AegisScan Report — {html.escape(str(result.target_path.name))}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  :root {{
    --bg:       #0d1117;
    --surface:  #161b22;
    --border:   #21262d;
    --text:     #c9d1d9;
    --muted:    #8b949e;
    --accent:   #58a6ff;
    --radius:   10px;
  }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Inter', system-ui, sans-serif;
    font-size: 14px;
    line-height: 1.6;
    padding: 32px 24px;
    max-width: 1200px;
    margin: 0 auto;
  }}

  /* Header */
  .header {{
    display: flex;
    align-items: center;
    gap: 16px;
    margin-bottom: 32px;
    padding-bottom: 24px;
    border-bottom: 1px solid var(--border);
  }}
  .logo {{ font-size: 1.5rem; font-weight: 700; color: var(--accent); letter-spacing: -0.5px; }}
  .logo span {{ color: var(--muted); font-weight: 400; }}
  .scan-meta {{ margin-left: auto; text-align: right; color: var(--muted); font-size: 0.8rem; }}
  .scan-meta strong {{ color: var(--text); }}

  /* Score gauges */
  .gauges {{ display: flex; gap: 24px; margin-bottom: 28px; flex-wrap: wrap; }}
  .gauge-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px 28px;
    text-align: center;
    min-width: 200px;
    transition: border-color 0.2s;
  }}
  .gauge-card:hover {{ border-color: var(--accent); }}
  .gauge-label {{ font-weight: 700; font-size: 1rem; margin-top: 4px; }}
  .gauge-sub {{ color: var(--muted); font-size: 0.75rem; margin-top: 2px; }}

  /* Summary cards */
  .summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 28px;
  }}
  .summary-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px 20px;
  }}
  .summary-card .label {{ color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  .summary-card .value {{ font-size: 1.6rem; font-weight: 700; margin-top: 4px; color: var(--accent); }}
  .summary-card .sub {{ color: var(--muted); font-size: 0.75rem; margin-top: 2px; }}

  /* Intelligence section */
  .intel-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px 20px;
    margin-bottom: 28px;
    display: flex;
    gap: 32px;
    flex-wrap: wrap;
    align-items: center;
  }}
  .intel-card .intel-item {{ text-align: center; }}
  .intel-card .intel-value {{ font-size: 1.4rem; font-weight: 700; color: var(--accent); }}
  .intel-card .intel-label {{ color: var(--muted); font-size: 0.75rem; margin-top: 2px; }}
  .intel-title {{ font-weight: 600; color: var(--text); font-size: 0.9rem; margin-right: 8px; }}

  /* Table */
  .table-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 12px;
  }}
  .section-title {{ font-size: 1.1rem; font-weight: 600; }}
  .count-badge {{ background: var(--border); border-radius: 20px; padding: 2px 10px; font-size: 0.8rem; color: var(--muted); }}

  table {{ width: 100%; border-collapse: collapse; }}
  thead th {{
    background: var(--surface);
    color: var(--muted);
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 10px 12px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }}
  .finding-row td {{
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
    transition: background 0.15s;
  }}
  .finding-row:hover td {{ background: rgba(88,166,255,0.04); }}

  .sev-badge {{
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 700;
    white-space: nowrap;
  }}
  .conf-pill {{
    color: var(--muted);
    font-size: 0.8rem;
    font-family: 'JetBrains Mono', monospace;
  }}
  .source-badge {{
    border: 1px solid;
    padding: 1px 7px;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
    white-space: nowrap;
  }}
  .file-cell {{ font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--accent); }}
  .line-num {{ color: var(--muted); }}
  .issue-cell {{ max-width: 260px; }}
  .cat-tag {{
    background: rgba(88,166,255,0.1);
    color: var(--muted);
    padding: 1px 6px;
    border-radius: 4px;
    font-size: 0.7rem;
    white-space: nowrap;
  }}
  .expand-icon {{ color: var(--muted); font-size: 0.8rem; }}

  /* Detail row */
  .detail-row td {{ padding: 0; }}
  .detail-content {{
    background: #0d1117;
    border-bottom: 1px solid var(--border);
    padding: 16px 20px;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 16px;
  }}
  .detail-section {{ }}
  .detail-label {{
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    margin-bottom: 6px;
  }}
  .code-block {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    white-space: pre-wrap;
    word-break: break-all;
    color: #f0e6d2;
    overflow: auto;
    max-height: 200px;
  }}
  .detail-text {{ color: var(--text); font-size: 0.85rem; line-height: 1.6; }}
  .fix-text {{ color: #3fb950; }}

  /* Footer */
  .footer {{
    margin-top: 40px;
    padding-top: 20px;
    border-top: 1px solid var(--border);
    color: var(--muted);
    font-size: 0.75rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  .note {{
    background: rgba(240,180,41,0.08);
    border: 1px solid rgba(240,180,41,0.2);
    border-radius: var(--radius);
    padding: 10px 16px;
    color: #f0b429;
    font-size: 0.8rem;
    margin-bottom: 24px;
  }}
</style>
</head>
<body>

<div class="header">
  <div>
    <div class="logo">Aegis<span>Scan</span></div>
    <div style="color:var(--muted);font-size:0.75rem;margin-top:2px">
      AI-Driven Workspace Security &amp; Optimization Scanner
    </div>
  </div>
  <div class="scan-meta">
    <div><strong>{html.escape(str(result.target_path))}</strong></div>
    <div>Scan ID: {html.escape(result.scan_id)}</div>
    <div>Generated: {now}</div>
    <div>Duration: {result.scan_duration_seconds:.2f}s</div>
  </div>
</div>

<div class="gauges">
  {_score_gauge(sec_score, "Security Score", f"{score_label(sec_score)} — {len([f for f in result.findings if f.category != 'performance'])} security findings")}
  {_score_gauge(opt_score, "Optimization Score", f"{score_label(opt_score)} — {len([f for f in result.findings if f.category == 'performance'])} performance findings")}
  <div class="gauge-card" style="flex:1;min-width:280px;text-align:left;padding:20px">
    <div class="label" style="color:var(--muted);font-size:0.75rem;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:10px">Toolchain</div>
    <div style="margin-bottom:6px"><span style="color:var(--muted)">Static:</span> {html.escape(tools_str)}</div>
    <div style="margin-bottom:6px"><span style="color:var(--muted)">LLM:</span> {html.escape(llm_str)}</div>
    <div><span style="color:var(--muted)">Chunks:</span> {result.chunks_created} ({result.llm_chunks_analyzed} sent to LLM)</div>
  </div>
</div>

<div class="summary-grid">
  <div class="summary-card">
    <div class="label">Total Findings</div>
    <div class="value">{len(result.findings)}</div>
    <div class="sub">{static_count} static · {llm_count} LLM</div>
  </div>
  <div class="summary-card">
    <div class="label">Files Analyzed</div>
    <div class="value">{result.files_analyzed}</div>
    <div class="sub">of {result.files_discovered} discovered</div>
  </div>
  <div class="summary-card">
    <div class="label">Critical / High</div>
    <div class="value" style="color:#ff4444">
      {len(findings_by_sev.get(Severity.CRITICAL,[]))} / {len(findings_by_sev.get(Severity.HIGH,[]))}
    </div>
    <div class="sub">require immediate attention</div>
  </div>
  <div class="summary-card">
    <div class="label">Medium / Low</div>
    <div class="value" style="color:#f0b429">
      {len(findings_by_sev.get(Severity.MEDIUM,[]))} / {len(findings_by_sev.get(Severity.LOW,[]))}
    </div>
    <div class="sub">should be addressed</div>
  </div>
</div>

<div class="intel-card">
  <span class="intel-title">V3 Intelligence</span>
  <div class="intel-item">
    <div class="intel-value">{result.findings_deduplicated}</div>
    <div class="intel-label">Deduplicated</div>
  </div>
  <div class="intel-item">
    <div class="intel-value">{result.findings_corroborated}</div>
    <div class="intel-label">Corroborated</div>
  </div>
  <div class="intel-item">
    <div class="intel-value">{result.findings_suppressed}</div>
    <div class="intel-label">Baseline Suppressed</div>
  </div>
</div>

{'<div class="intel-card"><span class="intel-title">V5 LLM Telemetry</span><div class="intel-item"><div class="intel-value">' + str(result.llm_requests_count) + '</div><div class="intel-label">API Requests</div></div><div class="intel-item"><div class="intel-value">' + str(result.llm_total_input_tokens) + '</div><div class="intel-label">Input Tokens</div></div><div class="intel-item"><div class="intel-value">' + str(result.llm_total_output_tokens) + '</div><div class="intel-label">Output Tokens</div></div><div class="intel-item"><div class="intel-value">' + f"{result.llm_total_latency_seconds:.2f}s" + '</div><div class="intel-label">API Latency</div></div><div class="intel-item"><div class="intel-value">' + str(result.llm_rate_limit_hits) + '</div><div class="intel-label">429 Rate Hits</div></div></div>' if result.llm_requests_count else ''}

{history_card_html}

<div class="note">
  ⚠ Scores are heuristic estimates (not calibrated against CVE datasets).
  Treat as directional signals, not absolute security guarantees.
</div>

<div class="table-header">
  <div class="section-title">Findings</div>
  <span class="count-badge">{len(result.findings)} total</span>
</div>

<table>
  <thead>
    <tr>
      <th>Severity</th>
      <th>Conf</th>
      <th>Source</th>
      <th>Location</th>
      <th>Issue</th>
      <th>Category</th>
      <th></th>
    </tr>
  </thead>
  <tbody>
    {rows_html if rows_html else '<tr><td colspan="7" style="text-align:center;padding:40px;color:var(--muted)">No findings — looking good!</td></tr>'}
  </tbody>
</table>

<div class="footer">
  <span>AegisScan V4 · Generated {now}</span>
  <span style="color:var(--muted)">Scan ID: {html.escape(result.scan_id[:8])}…</span>
</div>

<script>
function toggleDetail(id) {{
  const row = document.getElementById(id);
  if (!row) return;
  const isHidden = row.style.display === 'none';
  row.style.display = isHidden ? 'table-row' : 'none';
  // Rotate expand icon
  const tr = row.previousElementSibling;
  const icon = tr ? tr.querySelector('.expand-icon') : null;
  if (icon) icon.textContent = isHidden ? '▾' : '▸';
}}
</script>
</body>
</html>"""

    output_path.write_text(html_content, encoding="utf-8")
