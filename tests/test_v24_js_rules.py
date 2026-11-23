"""AegisScan's bundled Semgrep rules for JS sinks the registry packs miss (needs the semgrep binary).

Semgrep starts slowly, so every case lives in one fixture file that is scanned once per module.
"""
from __future__ import annotations

import json
import subprocess

import pytest

from scanner.static_analysis import semgrep_runner
from scanner.static_analysis.semgrep_runner import _LOCAL_RULES, _normalize

_SEMGREP = semgrep_runner._find_tool("semgrep")

# (marker, code, expected category or None when the rules must stay quiet)
_CASES = [
    ("eval_var",   "function f(x) { return eval(x); }", "injection"),
    ("fn_ctor",    "function f(t) { return new Function('a', t); }", "injection"),
    ("vm_exec",    "function f(t) { return vm.runInNewContext(t, {}); }", "injection"),
    ("doc_write",  "function f(q) { document.write('<h2>' + q + '</h2>'); }", "xss"),
    ("inner_html", "function f(el, s) { el.innerHTML = s; }", "xss"),
    ("join_read",  "function f(u, n) {\n  const p = path.join('/app', u, n);\n  return fs.readFileSync(p, 'utf8');\n}",
     "path_traversal"),
    ("eval_lit",   "function f() { return eval('1 + 1'); }", None),
    ("fn_lit",     "function f() { return new Function('return 1'); }", None),
    ("html_empty", "function f(el) { el.innerHTML = ''; }", None),
    ("write_lit",  "function f() { document.write('<b>static</b>'); }", None),
    ("callback",   "function f(cb) { setTimeout(cb, 10); }", None),
    ("join_const", "function f() {\n  const p = path.join(__dirname, 'data.json');\n  return fs.readFileSync(p, 'utf8');\n}",
     None),
    # --- v26: more DOM sinks, timers given code strings, string-built SQL, request-driven paths
    ("insert_adj", "function f(l, c) { l.insertAdjacentHTML('beforeend', '<li>' + c + '</li>'); }", "xss"),
    ("jquery_html", "function f(u) { $('#b').html(u.bio); }", "xss"),
    ("react_html", "function P({ p }) { return <div dangerouslySetInnerHTML={{ __html: p.content }} />; }", "xss"),
    ("timer_tpl", "function f(id) { setInterval(`refresh('${id}')`, 5); }", "injection"),
    ("timer_concat", "function f(id) { setTimeout('go(' + id + ')', 5); }", "injection"),
    ("timer_named", "function f(userCode) { setTimeout(userCode, 5); }", "injection"),
    ("sql_concat", "function f(db, id) { db.query('SELECT * FROM t WHERE id = ' + id); }", "injection"),
    ("sql_tpl", "function f(db, id) { db.query(`DELETE FROM t WHERE id = ${id}`); }", "injection"),
    ("send_file", "app.get('/f', (req, res) => { res.sendFile(req.params.file); });", "path_traversal"),
    ("read_req", "app.get('/r', (req, res) => { fs.readFile(path.join(DIR, req.query.name), cb); });",
     "path_traversal"),
    ("stream_req", "app.get('/s', (req, res) => { fs.createReadStream('./u/' + req.params.n); });",
     "path_traversal"),
    ("html_sanitized", "function f(el, s) { el.innerHTML = DOMPurify.sanitize(s); }", None),
    ("adj_sanitized", "function f(l, c) { l.insertAdjacentHTML('beforeend', DOMPurify.sanitize(c)); }", None),
    ("adj_literal", "function f(l) { l.insertAdjacentHTML('beforeend', '<hr>'); }", None),
    ("jquery_safe", "function f(u) { $('#b').text(u.bio); $('#c').html('<b>x</b>'); }", None),
    ("react_clean",
     "function P({ p }) { return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(p.content) }} />; }", None),
    ("timer_fn", "function f(tick, cb) { setTimeout(() => tick(), 1); setTimeout(cb, 2); setInterval(tick, 3); }", None),
    ("sql_param", "function f(db, id) { db.query('SELECT * FROM t WHERE id = $1', [id]); db.query('SELECT 1'); }", None),
    ("sql_not_sql", "function f(m, k) { m.get('key' + k); cache.query(`user:${k}`); }", None),
    ("send_root", "app.get('/f', (req, res) => { res.sendFile(req.params.file, { root: DIR }); });", None),
    ("read_const", "function f() { fs.readFile(path.join(__dirname, 'c.json'), cb); }", None),
]


@pytest.fixture(scope="module")
def scan(tmp_path_factory) -> dict[str, list[str]]:
    """{marker: categories of findings whose lines fall inside that case's block}."""
    if _SEMGREP is None:
        pytest.skip("semgrep not installed")
    root = tmp_path_factory.mktemp("jsrules")
    lines: list[str] = []
    spans: dict[str, tuple[int, int]] = {}
    for marker, code, _ in _CASES:
        start = len(lines) + 1
        lines += code.split("\n") + [""]
        spans[marker] = (start, len(lines) - 1)
    (root / "cases.js").write_text("\n".join(lines) + "\n", encoding="utf-8")
    proc = subprocess.run(
        [_SEMGREP, "scan", "--config", str(_LOCAL_RULES), "--metrics=off", "--json", "--quiet",
         "--no-git-ignore", "--project-root", str(root), str(root)],
        capture_output=True, text=True, timeout=600,
    )
    findings = [_normalize(r) for r in json.loads(proc.stdout)["results"]]
    return {m: [f.category for f in findings if lo <= f.line_start <= hi] for m, (lo, hi) in spans.items()}


def test_rules_file_ships_with_the_package():
    assert _LOCAL_RULES.is_file()


@pytest.mark.parametrize("marker, category", [(m, c) for m, _, c in _CASES if c])
def test_flags_dangerous_sink_with_its_own_category(scan, marker, category):
    assert category in scan[marker]


@pytest.mark.parametrize("marker", [m for m, _, c in _CASES if c is None])
def test_literals_and_callbacks_are_not_flagged(scan, marker):
    assert scan[marker] == []


def test_semgrep_repeated_matches_are_reported_once(monkeypatch, tmp_path):
    """Semgrep reports some matches several times; the runner keeps one per rule and range."""
    hit = {
        "check_id": "aegis-js-sql-string-building", "path": "a.js",
        "start": {"line": 3, "col": 1}, "end": {"line": 3, "col": 40},
        "extra": {"severity": "ERROR", "message": "m", "lines": "x", "metadata": {"aegis_category": "injection"}},
    }
    other = {**hit, "start": {"line": 9, "col": 1}, "end": {"line": 9, "col": 40}}
    payload = json.dumps({"results": [hit, dict(hit), dict(hit), other]})
    monkeypatch.setattr(semgrep_runner, "_find_tool", lambda name: "semgrep")
    monkeypatch.setattr(
        semgrep_runner, "_run_bounded",
        lambda cmd, timeout_s=None, **kw: subprocess.CompletedProcess(cmd, 0, stdout=payload, stderr=""),
    )

    findings = semgrep_runner.run_semgrep(tmp_path)

    assert sorted(f.line_start for f in findings) == [3, 9]
