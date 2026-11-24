"""AegisScan's bundled Semgrep rules for Java, Go, PHP and C# (needs the semgrep binary).

Semgrep starts slowly, so every snippet lives in one generated file per language and the four
files are scanned once per module. Each rule gets a vulnerable case and the guarded look-alikes
that must stay quiet.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scanner.static_analysis import semgrep_runner
from scanner.static_analysis.semgrep_runner import _LOCAL_RULE_FILES, _normalize

_SEMGREP = semgrep_runner._find_tool("semgrep")
ROOT = Path(__file__).resolve().parents[1]

# (marker, body, expected category or None when the rules must stay quiet)
JAVA = [
    ("exec_concat", 'Runtime.getRuntime().exec("ping " + s);', "injection"),
    ("exec_literal", 'Runtime.getRuntime().exec("ls");', None),
    ("exec_array", 'Runtime.getRuntime().exec(new String[]{"ping", "-c", "1", s});', None),
    ("pb_shell_concat", 'new ProcessBuilder("sh", "-c", "tar " + s).start();', "injection"),
    ("pb_shell_list", 'new ProcessBuilder(List.of("bash", "-c", s)).start();', "injection"),
    ("pb_shell_literal", 'new ProcessBuilder("sh", "-c", "echo hi").start();', None),
    ("pb_args", 'new ProcessBuilder("tar", "xf", s).start();', None),
    ("xxe_dbf_chain", "DocumentBuilderFactory.newInstance().newDocumentBuilder();", "injection"),
    ("xxe_sax_chain", "SAXParserFactory.newInstance().newSAXParser();", "injection"),
    ("xxe_dbf_var", "DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\nf.newDocumentBuilder();", "injection"),
    ("xxe_dbf_doctype",
     'DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n'
     'f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nf.newDocumentBuilder();', None),
    ("xxe_dbf_entities",
     'DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n'
     'f.setFeature("http://xml.org/sax/features/external-general-entities", false);\nf.newDocumentBuilder();', None),
    ("xxe_sax_var", "SAXParserFactory f = SAXParserFactory.newInstance();\nf.newSAXParser();", "injection"),
    ("xxe_sax_doctype",
     'SAXParserFactory f = SAXParserFactory.newInstance();\n'
     'f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nf.newSAXParser();', None),
    ("cipher_des", 'Cipher.getInstance("DES");', "crypto"),
    ("cipher_ecb", 'Cipher.getInstance("AES/ECB/PKCS5Padding");', "crypto"),
    ("cipher_aes_bare", 'Cipher.getInstance("AES");', "crypto"),
    ("cipher_gcm", 'Cipher.getInstance("AES/GCM/NoPadding");', None),
    ("cipher_variable", "Cipher.getInstance(alg);", None),
    ("redirect_req", 'resp.sendRedirect(req.getParameter("n"));', "redirect"),
    ("redirect_literal", 'resp.sendRedirect("/home");', None),
    ("redirect_checked", 'String n = req.getParameter("n");\nresp.sendRedirect(ok(n) ? n : "/");', None),
    ("path_file", 'new File("/srv", req.getParameter("n"));', "path_traversal"),
    ("path_fis_nested", 'new FileInputStream(new File("/srv", req.getParameter("n")));', "path_traversal"),
    ("path_const", 'new File("/srv", "fixed.txt");', None),
]

GO = [
    ("exec_sh_concat", 'exec.Command("sh", "-c", "ping "+s).Run()', "injection"),
    ("exec_ctx", 'exec.CommandContext(ctx, "bash", "-c", s).Run()', "injection"),
    ("exec_sh_literal", 'exec.Command("sh", "-c", "echo hi").Run()', None),
    ("exec_args", 'exec.Command("ping", "-c", "1", s).Run()', None),
    ("redirect_query", "http.Redirect(w, r, r.URL.Query().Get(\"next\"), 302)", "redirect"),
    ("redirect_form", 'http.Redirect(w, r, r.FormValue("next"), 302)', "redirect"),
    ("redirect_literal", 'http.Redirect(w, r, "/home", 302)', None),
    ("redirect_checked", 'target := safe(r.FormValue("next"))\nhttp.Redirect(w, r, target, 302)', None),
    ("tmpl_html", "_ = template.HTML(s)", "xss"),
    ("tmpl_js", "_ = template.JS(s)", "xss"),
    ("tmpl_literal", '_ = template.HTML("<b>x</b>")', None),
    ("path_readfile", 'os.ReadFile(filepath.Join("/srv", r.FormValue("n")))', "path_traversal"),
    ("path_open", 'os.Open("/srv/" + r.URL.Query().Get("f"))', "path_traversal"),
    ("path_servefile", 'http.ServeFile(w, r, r.FormValue("f"))', "path_traversal"),
    ("path_variable", "os.ReadFile(full)", None),
    ("path_const", 'os.Open("/srv/logo.png")', None),
]

PHP = [
    ("include_get", 'include($_GET["p"] . ".php");', "path_traversal"),
    ("require_post", 'require_once($_POST["p"]);', "path_traversal"),
    ("include_const", 'include(__DIR__ . "/p/home.php");', None),
    ("include_checked", 'include(__DIR__ . "/p/" . $page . ".php");', None),
    ("unser_cookie", 'unserialize($_COOKIE["c"]);', "deserialization"),
    ("unser_file", 'unserialize(file_get_contents("c.bin"), ["allowed_classes" => false]);', None),
    ("eval_var", "eval($code);", "injection"),
    ("eval_literal", 'eval("return 1;");', None),
    ("extract_post", "extract($_POST);", "injection"),
    ("extract_array", "extract($row, EXTR_SKIP);", None),
    ("md5_password", 'md5($_POST["password"]);', "crypto"),
    ("sha1_pwd", "sha1($pwd);", "crypto"),
    ("md5_body", "md5($body);", None),
    ("password_hash", "password_hash($password, PASSWORD_DEFAULT);", None),
    ("redirect_get", 'header("Location: " . $_GET["n"]);', "redirect"),
    ("redirect_var", 'header("Location: " . $next);', None),
    # found on DVWA: lowercase header name, a space before "(", single quotes, extra arguments
    ("redirect_lowercase_space", 'header ("location: " . $_GET["redirect"]);', "redirect"),
    ("redirect_single_quotes", "header('Location: ' . $_POST['to'], true, 302);", "redirect"),
    ("redirect_other_header", 'header("X-Next: " . $_GET["n"]);', None),
    ("header_other", 'header("Content-Type: text/plain");', None),
    ("fgc_get", 'file_get_contents("/srv/" . $_GET["f"]);', "path_traversal"),
    ("fopen_req", 'fopen($_REQUEST["log"], "r");', "path_traversal"),
    ("readfile_basename", 'readfile(__DIR__ . "/f/" . basename($_GET["f"]));', None),
    ("fopen_const", 'fopen(__DIR__ . "/app.log", "r");', None),
]

CSHARP = [
    ("md5", "MD5.Create();", "crypto"),
    ("sha1", "SHA1.Create();", "crypto"),
    ("md5_provider", "new MD5CryptoServiceProvider();", "crypto"),
    ("sha256", "SHA256.Create();", None),
    ("ps_concat", 'Process.Start("cmd.exe", "/c ping " + host);', "injection"),
    ("ps_interp", 'Process.Start("ping", $"-n 1 {host}");', "injection"),
    ("ps_literal", 'Process.Start("notepad.exe", "readme.txt");', None),
    ("psi_plain", 'var psi = new ProcessStartInfo("ping");', None),
    ("xml_resolver", "var r = new XmlUrlResolver();", "injection"),
    ("xml_null", "doc.XmlResolver = null;", None),
    ("dtd_parse", "var s = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };", "injection"),
    ("dtd_prohibit", "var s = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };", None),
    ("tls_true", "ServicePointManager.ServerCertificateValidationCallback = (a, b, c, d) => true;", "network"),
    ("tls_handler", "var h = new HttpClientHandler { ServerCertificateCustomValidationCallback = (m, c, ch, e) => true };",
     "network"),
    ("tls_dangerous",
     "var h = new HttpClientHandler { ServerCertificateCustomValidationCallback = "
     "HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };", "network"),
    ("tls_checked", "ServicePointManager.ServerCertificateValidationCallback = (a, b, c, d) => d == SslPolicyErrors.None;",
     None),
    ("redirect_query", 'return Redirect(Request.Query["next"]);', "redirect"),
    ("redirect_local", 'return LocalRedirect(next);', None),
    ("file_query", 'File.ReadAllText("/srv/" + Request.Query["n"]);', "path_traversal"),
    ("file_filename", 'File.ReadAllText(Path.Combine("/srv", Path.GetFileName(Request.Query["n"])));', None),
    ("html_concat", 'new HtmlString("<b>" + bio + "</b>");', "xss"),
    ("html_raw", "Html.Raw(model.Bio);", "xss"),
    ("html_encoded", 'new HtmlString("<b>" + HtmlEncoder.Default.Encode(bio) + "</b>");', None),
    ("html_literal", 'new HtmlString("<b>x</b>");', None),
]

_LANGS = {
    "java": (JAVA, "java", lambda m, body: f"void {m}() throws Exception {{\n{body}\n}}", "class Cases {\n", "}\n"),
    "go": (GO, "go", lambda m, body: f"func {m}() {{\n{body}\n}}", "package main\n", ""),
    "php": (PHP, "php", lambda m, body: body, "<?php\n", ""),
    "csharp": (CSHARP, "cs", lambda m, body: f"void {m}() {{\n{body}\n}}", "class Cases {\n", "}\n"),
}
_ALL = [(lang, m, c) for lang, (cases, *_rest) in _LANGS.items() for m, _body, c in cases]


@pytest.fixture(scope="module")
def scan(tmp_path_factory) -> dict[tuple[str, str], list[str]]:
    """{(language, marker): categories of the findings that fall inside that case's block}."""
    if _SEMGREP is None:
        pytest.skip("semgrep not installed")
    root = tmp_path_factory.mktemp("langrules")
    spans: dict[tuple[str, str], tuple[str, int, int]] = {}
    for lang, (cases, ext, wrap, head, tail) in _LANGS.items():
        lines = head.rstrip("\n").split("\n")
        for marker, body, _ in cases:
            start = len(lines) + 1
            lines += wrap(marker, body).split("\n") + [""]
            spans[(lang, marker)] = (f"cases.{ext}", start, len(lines) - 1)
        if tail:
            lines.append(tail.strip())
        (root / f"cases.{ext}").write_text("\n".join(lines) + "\n", encoding="utf-8")
    cmd = [_SEMGREP, "scan", *(a for f in _LOCAL_RULE_FILES for a in ("--config", str(f))),
           "--metrics=off", "--json", "--quiet", "--no-git-ignore", "--project-root", str(root), str(root)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    data = json.loads(proc.stdout)
    errors = [e for e in data.get("errors", []) if e.get("level") == "error"]
    assert not errors, errors
    found = [(Path(r["path"]).name, _normalize(r)) for r in data["results"]]
    return {
        key: [f.category for name, f in found if name == fname and lo <= f.line_start <= hi]
        for key, (fname, lo, hi) in spans.items()
    }


def test_every_language_has_its_own_rules_file():
    names = {p.name for p in _LOCAL_RULE_FILES}
    assert {"java_security.yml", "go_security.yml", "php_security.yml", "csharp_security.yml"} <= names


@pytest.mark.parametrize("lang, marker, category", [t for t in _ALL if t[2]])
def test_flags_dangerous_sink_with_its_own_category(scan, lang, marker, category):
    assert category in scan[(lang, marker)]


@pytest.mark.parametrize("lang, marker", [(lang, m) for lang, m, c in _ALL if c is None])
def test_guarded_and_literal_look_alikes_are_not_flagged(scan, lang, marker):
    assert scan[(lang, marker)] == []


@pytest.mark.parametrize("lang, marker", [(lang, m) for lang, m, c in _ALL if c])
def test_each_vulnerable_case_is_reported_once_per_rule(scan, lang, marker):
    """Nested or chained patterns must not report the same line twice."""
    assert len(scan[(lang, marker)]) == len(set(scan[(lang, marker)]))


# ------------------------------------------------------------------ benchmark fixtures
_MULTI = ROOT / "examples" / "benchmark_multilang"
_SAFE_TWINS = [
    "java/SafeUserService.java", "java/SafeMoreSinks.java", "go/safe_server.go", "go/safe_more_sinks.go",
    "php/safe.php", "php/safe_more_sinks.php", "csharp/SafeAccountService.cs", "csharp/SafeMoreSinks.cs",
]
# labels that no registry pack catches (the reason these rules exist): (file, label start line)
_FORMERLY_MISSED = [
    ("java/UserService.java", 39), ("java/UserService.java", 43), ("go/server.go", 25),
    ("php/index.php", 9), ("php/index.php", 11), ("php/index.php", 13), ("php/index.php", 19),
    ("csharp/AccountService.cs", 26), ("csharp/AccountService.cs", 36), ("csharp/AccountService.cs", 41),
]
_NEW_FIXTURES = ["java/MoreSinks.java", "go/more_sinks.go", "php/more_sinks.php", "csharp/MoreSinks.cs"]


@pytest.fixture(scope="module")
def fixture_hits() -> dict[str, list[tuple[int, int]]]:
    if _SEMGREP is None:
        pytest.skip("semgrep not installed")
    cmd = [_SEMGREP, "scan", *(a for f in _LOCAL_RULE_FILES for a in ("--config", str(f))),
           "--metrics=off", "--json", "--quiet", "--no-git-ignore", "--project-root", str(_MULTI), str(_MULTI)]
    data = json.loads(subprocess.run(cmd, capture_output=True, text=True, timeout=600).stdout)
    hits: dict[str, list[tuple[int, int]]] = {}
    for r in data["results"]:
        rel = Path(r["path"]).resolve().relative_to(_MULTI.resolve()).as_posix()
        hits.setdefault(rel, []).append((r["start"]["line"], r["end"]["line"]))
    return hits


def _covered(hits: list[tuple[int, int]], start: int, end: int) -> bool:
    return any(lo <= end + 1 and hi >= start - 1 for lo, hi in hits)


def test_safe_twin_fixtures_raise_nothing(fixture_hits):
    assert {f: fixture_hits[f] for f in _SAFE_TWINS if f in fixture_hits} == {}


def test_labels_no_registry_pack_catches_are_now_found(fixture_hits):
    missing = [(f, ln) for f, ln in _FORMERLY_MISSED if not _covered(fixture_hits.get(f, []), ln, ln)]
    assert missing == []


@pytest.mark.parametrize("rel", _NEW_FIXTURES)
def test_every_label_in_the_new_fixtures_is_found(fixture_hits, rel):
    manifest = json.loads((ROOT / "examples" / "benchmark_labels.json").read_text(encoding="utf-8"))
    labels = next(e["labels"] for e in manifest["files"] if e["path"] == f"benchmark_multilang/{rel}")
    assert labels, "fixture has no labels"
    missing = [lab["lines"] for lab in labels if not _covered(fixture_hits.get(rel, []), *lab["lines"])]
    assert missing == []
