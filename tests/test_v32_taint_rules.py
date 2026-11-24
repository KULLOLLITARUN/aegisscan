"""Bundled taint rules: a request value reaches a sink through a variable (needs the semgrep binary).

Each case is a small file; the rules run once over all of them and a case passes when the
`aegis-*-taint-*` rules do (or do not) report it. Safe cases use the standard fix.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scanner.static_analysis import semgrep_runner

_RULES = Path(semgrep_runner.__file__).parent / "rules"
_SEMGREP = semgrep_runner._find_tool("semgrep")
_EXAMPLES = Path(__file__).resolve().parents[1] / "examples"

PHP = [
    # (marker, body, expected rule suffix or None)
    ("inc_var", '$p = $_GET["page"];\ninclude($p);', "php-taint-file-inclusion"),
    ("require_once_var", '$p = $_POST["m"];\nrequire_once($p);', "php-taint-file-inclusion"),
    ("inc_concat", '$p = $_REQUEST["m"];\ninclude("pages/" . $p);', "php-taint-file-inclusion"),
    ("inc_basename", '$p = basename($_GET["page"]);\ninclude("pages/" . $p);', None),
    ("inc_literal", 'include(__DIR__ . "/header.php");', None),
    ("inc_allow_list", '$p = $_GET["page"];\nif (in_array($p, ["a", "b"], true)) {\n    include("pages/" . $p . ".php");\n}', None),
    ("inc_unguarded_neighbour", '$q = $_GET["q"];\nif (in_array("x", ["a"], true)) {\n    include($q);\n}', "php-taint-file-inclusion"),
    ("echo_var", '$n = $_GET["name"];\necho "Hello " . $n;', "php-taint-xss"),
    ("print_in_function", 'function show($k) {\n    $v = $_REQUEST[$k];\n    print $v;\n}', "php-taint-xss"),
    ("echo_escaped", '$n = htmlspecialchars($_GET["name"], ENT_QUOTES);\necho "Hello " . $n;', None),
    ("echo_cast", '$n = (int) $_GET["id"];\necho $n;', None),
    ("echo_numeric_guard", '$n = $_GET["id"];\nif (is_numeric($n)) {\n    echo $n;\n}', None),
    ("echo_not_request", '$n = "fixed";\necho $n;', None),
    ("shell_var", '$h = $_POST["host"];\nshell_exec("ping " . $h);', "php-taint-command-injection"),
    ("system_var", '$h = $_GET["h"];\nsystem("ls " . $h);', "php-taint-command-injection"),
    ("shell_escaped", '$h = escapeshellarg($_POST["host"]);\nshell_exec("ping " . $h);', None),
    ("shell_literal", 'shell_exec("uptime");', None),
]

JS = [
    ("xss_concat", "app.get('/a', (req, res) => {\n  const n = req.query.name;\n  res.send('Hello ' + n);\n});", "js-taint-reflected-xss"),
    ("xss_template", "app.get('/a', (req, res) => {\n  const n = req.params.name;\n  res.send(`Hello ${n}`);\n});", "js-taint-reflected-xss"),
    ("xss_write", "app.get('/a', (req, res) => {\n  const n = req.body.name;\n  res.write('<p>' + n);\n});", "js-taint-reflected-xss"),
    ("xss_escaped", "app.get('/a', (req, res) => {\n  const n = escapeHtml(req.query.name);\n  res.send('Hello ' + n);\n});", None),
    ("xss_number", "app.get('/a', (req, res) => {\n  const n = parseInt(req.params.id, 10);\n  res.send(`id ${n}`);\n});", None),
    ("xss_not_request", "app.get('/a', (req, res) => {\n  const n = lookup();\n  res.send('Hello ' + n);\n});", None),
    ("xss_object", "app.get('/a', (req, res) => {\n  const n = req.query.name;\n  res.send({ name: n });\n});", None),
    ("path_readfile", "app.get('/f', (req, res) => {\n  const f = req.query.file;\n  fs.readFile('/srv/' + f, cb);\n});", "js-taint-path-traversal"),
    ("path_basename", "app.get('/f', (req, res) => {\n  const f = path.basename(req.query.file);\n  fs.readFile('/srv/' + f, cb);\n});", None),
    ("path_download_root", "app.get('/f', (req, res) => {\n  const f = req.params.file;\n  res.download(f, { root: DIR }, cb);\n});", None),
    ("path_sendfile_no_root", "app.get('/f', (req, res) => {\n  const f = req.query.file;\n  res.sendFile(f);\n});", "js-taint-path-traversal"),
    ("cmd_exec", "app.post('/p', (req, res) => {\n  const h = req.body.host;\n  exec('ping ' + h);\n});", "js-taint-command-injection"),
    ("cmd_cp_exec_sync", "app.post('/p', (req, res) => {\n  const h = req.query.host;\n  cp.execSync(`ping ${h}`);\n});", "js-taint-command-injection"),
    ("cmd_execfile", "app.post('/p', (req, res) => {\n  execFile('ping', ['-c', '1', req.body.host]);\n});", None),
    ("cmd_literal", "exec('uptime');", None),
]


@pytest.fixture(scope="module")
def scan(tmp_path_factory) -> dict[str, set[str]]:
    """{case marker (file stem): ids of the bundled taint rules that fired on it}."""
    if _SEMGREP is None:
        pytest.skip("semgrep not installed")
    root = tmp_path_factory.mktemp("taint")
    for marker, body, _ in PHP:
        (root / f"{marker}.php").write_text("<?php\n" + body + "\n", encoding="utf8")
    for marker, body, _ in JS:
        (root / f"{marker}.js").write_text(body + "\n", encoding="utf8")
    proc = subprocess.run(
        [_SEMGREP, "--config", str(_RULES / "php_security.yml"), "--config", str(_RULES / "js_security.yml"),
         "--json", "--quiet", "--metrics=off", str(root)],
        capture_output=True, text=True, timeout=600,
    )
    data = json.loads(proc.stdout)
    assert not data["errors"], data["errors"][:1]
    out: dict[str, set[str]] = {}
    for r in data["results"]:
        rule = r["check_id"].split(".")[-1]
        if "-taint-" in rule:
            out.setdefault(Path(r["path"]).stem, set()).add(rule.removeprefix("aegis-"))
    return out


@pytest.mark.parametrize("marker, expected", [(m, e) for m, _, e in PHP + JS if e])
def test_flow_through_a_variable_is_flagged(scan, marker, expected):
    assert scan.get(marker) == {expected}


@pytest.mark.parametrize("marker", [m for m, _, e in PHP + JS if e is None])
def test_standard_fixes_and_non_request_values_are_not_flagged(scan, marker):
    assert scan.get(marker, set()) == set()


@pytest.mark.skipif(_SEMGREP is None, reason="semgrep not installed")
def test_benchmark_fixtures_hit_the_labelled_lines_and_twins_stay_clean():
    def taint_hits(path: Path) -> set[int]:
        proc = subprocess.run(
            [_SEMGREP, "--config", str(_RULES / "php_security.yml"), "--config", str(_RULES / "js_security.yml"),
             "--json", "--quiet", "--metrics=off", str(path)],
            capture_output=True, text=True, timeout=300,
        )
        return {r["start"]["line"] for r in json.loads(proc.stdout)["results"] if "-taint-" in r["check_id"]}

    assert taint_hits(_EXAMPLES / "benchmark_multilang" / "php" / "taint_flows.php") == {4, 7, 10, 14}
    assert taint_hits(_EXAMPLES / "vulnerable_js" / "taint_flows.js") == {8, 13, 18}
    assert taint_hits(_EXAMPLES / "benchmark_multilang" / "php" / "safe_taint_flows.php") == set()
    assert taint_hits(_EXAMPLES / "tricky_clean_js" / "safe_taint_flows.js") == set()
    # the pre-existing safe twin that uses an allow-list before include()
    assert taint_hits(_EXAMPLES / "benchmark_multilang" / "php" / "safe.php") == set()
