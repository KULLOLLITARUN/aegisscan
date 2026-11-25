"""Coverage tests for the SSE scan path and the Semgrep / Gitleaks runners.

External processes and the scan pipeline are mocked, so these run in milliseconds
and do not need the real tools installed.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from scanner.server.app import AegisScanRequestHandler
from scanner.static_analysis import gitleaks_runner, semgrep_runner
from tests.test_v10_server import _create_mock_request_handler


# ---------------------------------------------------------------- SSE helpers
def _events(handler: AegisScanRequestHandler) -> list[tuple[str, dict]]:
    """Parse the SSE payload written to the handler's wfile."""
    raw = handler.wfile.getvalue().decode("utf-8")
    events = []
    for block in raw.split("\n\n"):
        if not block.strip():
            continue
        lines = block.split("\n")
        name = lines[0].removeprefix("event: ")
        data = json.loads(lines[1].removeprefix("data: "))
        events.append((name, data))
    return events


def _fake_result(n_findings: int = 2) -> SimpleNamespace:
    payload = {"scan_id": "abc", "findings": [{}] * n_findings}
    return SimpleNamespace(
        findings=[object()] * n_findings,
        model_dump_json=lambda: json.dumps(payload),
    )


# ---------------------------------------------------------------- SSE tests
def test_sse_scan_streams_progress_and_complete(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_ALLOWED_ROOTS", str(tmp_path))
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    seen: dict = {}

    def fake_run(**kwargs):
        seen.update(kwargs)
        return _fake_result(2), None, None

    monkeypatch.setattr("main.run", fake_run)
    handler = _create_mock_request_handler(
        "GET", f"/api/scan/stream?path={tmp_path}&static_only=true"
    )
    handler.do_GET()

    handler.send_response.assert_called_with(200)
    events = _events(handler)
    names = [n for n, _ in events]
    assert "progress" in names
    assert names[-1] == "complete"
    assert events[-1][1]["scan_id"] == "abc"
    assert seen["static_only"] is True
    assert Path(seen["path"]) == tmp_path.resolve()
    final_progress = [d for n, d in events if n == "progress"][-1]
    assert final_progress["pct"] == 100 and final_progress["found"] == 2


def test_sse_strict_privacy_forces_static_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_ALLOWED_ROOTS", str(tmp_path))
    seen: dict = {}

    def fake_run(**kwargs):
        seen.update(kwargs)
        return _fake_result(0), None, None

    monkeypatch.setattr("main.run", fake_run)
    handler = _create_mock_request_handler(
        "GET",
        f"/api/scan/stream?path={tmp_path}&static_only=false&deep=true"
        "&generate_patches=true&privacy=strict",
    )
    handler.do_GET()
    assert seen["static_only"] is True
    assert seen["deep"] is False
    assert seen["generate_patches"] is False
    assert seen["privacy"] == "strict"


def test_sse_reports_run_exception_as_error_event(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_ALLOWED_ROOTS", str(tmp_path))

    def boom(**kwargs):
        raise RuntimeError("scan blew up")

    monkeypatch.setattr("main.run", boom)
    handler = _create_mock_request_handler("GET", f"/api/scan/stream?path={tmp_path}")
    handler.do_GET()
    events = _events(handler)
    assert events[-1][0] == "error"
    assert "scan blew up" in events[-1][1]["error"]


def test_sse_missing_path_yields_error_event(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_ALLOWED_ROOTS", str(tmp_path))
    missing = tmp_path / "nope"
    handler = _create_mock_request_handler("GET", f"/api/scan/stream?path={missing}")
    handler.do_GET()
    events = _events(handler)
    assert events[0][0] == "error"
    assert "does not exist" in events[0][1]["error"]


def test_sse_file_path_yields_error_event(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_ALLOWED_ROOTS", str(tmp_path))
    f = tmp_path / "file.py"
    f.write_text("x=1\n", encoding="utf-8")
    handler = _create_mock_request_handler("GET", f"/api/scan/stream?path={f}")
    handler.do_GET()
    events = _events(handler)
    assert events[0][0] == "error"
    assert "not a directory" in events[0][1]["error"]


def test_sse_rejects_path_outside_allowed_roots(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("AEGISSCAN_ALLOWED_ROOTS", raising=False)
    handler = _create_mock_request_handler("GET", f"/api/scan/stream?path={tmp_path}")
    handler.do_GET()
    handler.send_response.assert_called_with(403)


def test_sse_log_handler_forwards_records(tmp_path: Path, monkeypatch) -> None:
    import logging

    monkeypatch.setenv("AEGISSCAN_ALLOWED_ROOTS", str(tmp_path))

    def chatty_run(**kwargs):
        logging.getLogger("scanner.test").info("provider failover happened")
        return _fake_result(0), None, None

    monkeypatch.setattr("main.run", chatty_run)
    handler = _create_mock_request_handler("GET", f"/api/scan/stream?path={tmp_path}")
    handler.do_GET()
    logs = [d for n, d in _events(handler) if n == "log"]
    assert any("provider failover happened" in d["message"] for d in logs)
    # handler must be detached afterwards
    assert not any(
        type(h).__name__ == "_SSELogHandler" for h in logging.getLogger().handlers
    )


def test_sse_query_api_key_is_exported(tmp_path: Path, monkeypatch) -> None:
    import os

    monkeypatch.setenv("AEGISSCAN_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setattr("main.run", lambda **kw: (_fake_result(0), None, None))
    handler = _create_mock_request_handler(
        "GET", f"/api/scan/stream?path={tmp_path}&api_key=test-key-not-real"
    )
    handler.do_GET()
    assert os.environ["GROQ_API_KEY"] == "test-key-not-real"
    monkeypatch.delenv("GROQ_API_KEY", raising=False)


def test_sync_scan_error_returns_500(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_ALLOWED_ROOTS", str(tmp_path))

    def boom(**kwargs):
        raise RuntimeError("nope")

    monkeypatch.setattr("main.run", boom)
    handler = _create_mock_request_handler(
        "POST", "/api/scan", body={"path": str(tmp_path)}
    )
    handler.do_POST()
    handler.send_response.assert_called_with(500)


def test_sync_scan_invalid_path_returns_400(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_ALLOWED_ROOTS", str(tmp_path))
    handler = _create_mock_request_handler(
        "POST", "/api/scan", body={"path": str(tmp_path / "missing")}
    )
    handler.do_POST()
    handler.send_response.assert_called_with(400)


def test_unknown_post_endpoint_is_404() -> None:
    handler = _create_mock_request_handler("POST", "/api/other", body={})
    handler.do_POST()
    handler.send_error.assert_called()
    assert handler.send_error.call_args.args[0] == 404


def test_assets_route_serves_and_404s(monkeypatch, tmp_path: Path) -> None:
    import scanner.server.app as app

    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "x.js").write_text("console.log(1)", encoding="utf-8")
    monkeypatch.setattr(app, "_DIST_DIR", tmp_path)

    ok = _create_mock_request_handler("GET", "/assets/x.js")
    ok.do_GET()
    ok.send_response.assert_called_with(200)
    assert b"console.log" in ok.wfile.getvalue()

    missing = _create_mock_request_handler("GET", "/assets/none.js")
    missing.do_GET()
    missing.send_error.assert_called()


# ---------------------------------------------------------------- semgrep
_SEMGREP_JSON = {
    "results": [
        {
            "check_id": "python.lang.security.audit.exec-detected",
            "path": "app.py",
            "start": {"line": 3},
            "end": {"line": 4},
            "extra": {"severity": "ERROR", "message": "exec used", "lines": " exec(x) "},
        },
        {
            "check_id": "generic.style",
            "path": "b.py",
            "start": {"line": 1},
            "extra": {"severity": "WEIRD", "message": "odd"},
        },
        {"bad": "item without path"},
    ]
}


def _patch_semgrep(monkeypatch, stdout: str = "", exc: Exception | None = None):
    monkeypatch.setattr(semgrep_runner, "_find_tool", lambda name: "semgrep")

    def fake_run(cmd, timeout_s=None, **kwargs):
        if exc:
            raise exc
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(semgrep_runner, "_run_bounded", fake_run)


def test_semgrep_timeout_is_shorter_in_hosted_mode(monkeypatch) -> None:
    monkeypatch.delenv("AEGISSCAN_SEMGREP_TIMEOUT_S", raising=False)
    monkeypatch.delenv("AEGISSCAN_MODE", raising=False)
    assert semgrep_runner._semgrep_timeout() == 300
    monkeypatch.setenv("AEGISSCAN_MODE", "hosted")
    assert semgrep_runner._semgrep_timeout() == 150
    monkeypatch.setenv("AEGISSCAN_SEMGREP_TIMEOUT_S", "40")
    assert semgrep_runner._semgrep_timeout() == 40


def test_run_bounded_stops_a_process_that_runs_too_long() -> None:
    import sys
    import time
    t0 = time.time()
    with pytest.raises(subprocess.TimeoutExpired):
        semgrep_runner._run_bounded([sys.executable, "-c", "import time; time.sleep(60)"], 1)
    assert time.time() - t0 < 15


def test_semgrep_missing_binary_returns_empty(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(semgrep_runner, "_find_tool", lambda name: None)
    assert semgrep_runner.run_semgrep(tmp_path) == []


def test_semgrep_normalizes_results(monkeypatch, tmp_path: Path) -> None:
    _patch_semgrep(monkeypatch, json.dumps(_SEMGREP_JSON))
    findings = semgrep_runner.run_semgrep(tmp_path)
    assert len(findings) == 2  # malformed item skipped
    first, second = findings
    assert first.severity.value.lower() == "high"
    assert first.confidence == 0.80
    assert first.category == "injection"
    assert (first.line_start, first.line_end) == (3, 4)
    assert first.evidence == "exec(x)"
    assert first.rule_source == "semgrep"
    assert second.severity.value.lower() == "info"
    assert second.line_end == 1


@pytest.mark.parametrize(
    "stdout,exc",
    [
        ("", None),
        ("not json", None),
        ("", subprocess.TimeoutExpired("semgrep", 1)),
        ("", OSError("boom")),
    ],
)
def test_semgrep_degrades_gracefully(monkeypatch, tmp_path: Path, stdout, exc) -> None:
    _patch_semgrep(monkeypatch, stdout, exc)
    assert semgrep_runner.run_semgrep(tmp_path) == []


@pytest.mark.parametrize(
    "rule,cat",
    [
        ("x.sql-injection", "injection"),
        ("x.hardcoded-password", "secrets"),
        ("x.csrf-missing", "access_control"),
        ("x.weak-hash", "crypto"),
        ("x.n+1-query", "performance"),
        ("x.something-else", "best_practices"),
    ],
)
def test_semgrep_category_inference(rule: str, cat: str) -> None:
    assert semgrep_runner._infer_category(rule) == cat


def test_find_tool_uses_path_then_venv(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(semgrep_runner.shutil, "which", lambda n: "/usr/bin/" + n)
    assert semgrep_runner._find_tool("semgrep") == "/usr/bin/semgrep"

    monkeypatch.setattr(semgrep_runner.shutil, "which", lambda n: None)
    monkeypatch.setattr(semgrep_runner.sys, "prefix", str(tmp_path))
    assert semgrep_runner._find_tool("semgrep") is None
    (tmp_path / "bin").mkdir()
    exe = tmp_path / "bin" / "semgrep"
    exe.write_text("", encoding="utf-8")
    assert semgrep_runner._find_tool("semgrep") == str(exe)


# ---------------------------------------------------------------- gitleaks
_GITLEAKS_JSON = [
    {
        "File": "cfg.py",
        "Description": "AWS key",
        "StartLine": 5,
        "EndLine": 6,
        "Secret": " AKIAxxxx ",
        "RuleID": "aws-access-token",
        "Entropy": 3.2,
    }
]


def _patch_gitleaks(monkeypatch, report_text: str | None, exc: Exception | None = None):
    """Fake gitleaks binary: writes report_text to the --report-path argument."""
    monkeypatch.setattr(gitleaks_runner, "_find_tool", lambda name: "gitleaks")

    def fake_run(cmd, **kwargs):
        if exc:
            raise exc
        if report_text is not None:
            Path(cmd[cmd.index("--report-path") + 1]).write_text(report_text, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(gitleaks_runner.subprocess, "run", fake_run)


def test_gitleaks_normalizes_report(monkeypatch, tmp_path: Path) -> None:
    _patch_gitleaks(monkeypatch, json.dumps(_GITLEAKS_JSON))
    findings = gitleaks_runner.run_gitleaks(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "secrets"
    assert f.evidence == "[REDACTED]"   # the report carries the secret; the finding must not
    assert (f.line_start, f.line_end) == (5, 6)
    assert "aws-access-token" in f.explanation


@pytest.mark.parametrize("text", ["", "null", '{"not": "a list"}', "garbage"])
def test_gitleaks_empty_or_bad_report_returns_empty(monkeypatch, tmp_path: Path, text) -> None:
    _patch_gitleaks(monkeypatch, text)
    assert gitleaks_runner.run_gitleaks(tmp_path) == []


def test_gitleaks_subprocess_failure_falls_back_to_python_scanner(
    monkeypatch, tmp_path: Path
) -> None:
    (tmp_path / "leak.py").write_text('key = "AKIAABCDEFGHIJKLMNOP"\n', encoding="utf-8")
    _patch_gitleaks(monkeypatch, None, exc=subprocess.TimeoutExpired("gitleaks", 1))
    findings = gitleaks_runner.run_gitleaks(tmp_path)
    assert any(f.issue_type == "AWS Access Key ID" for f in findings)


def test_gitleaks_absent_uses_python_scanner(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(gitleaks_runner, "_find_tool", lambda name: None)
    (tmp_path / "s.py").write_text('password = "hunter2hunter2"\n', encoding="utf-8")
    findings = gitleaks_runner.run_gitleaks(tmp_path)
    assert [f.issue_type for f in findings] == ["Hardcoded Password String"]


def test_python_scanner_single_file_and_ignored_dirs(tmp_path: Path) -> None:
    f = tmp_path / "one.py"
    f.write_text('api_secret = "abcdefgh1234"\n', encoding="utf-8")
    assert len(gitleaks_runner._run_python_secret_scanner(f)) == 1

    ignored = tmp_path / "node_modules"
    ignored.mkdir()
    (ignored / "dep.js").write_text('const p = "x"; password = "secret123"\n', encoding="utf-8")
    only_ignored = tmp_path / "proj"
    only_ignored.mkdir()
    (only_ignored / "node_modules").mkdir()
    (only_ignored / "node_modules" / "dep.js").write_text(
        'password = "secret123"\n', encoding="utf-8"
    )
    assert gitleaks_runner._run_python_secret_scanner(only_ignored) == []


def test_python_scanner_missing_target_returns_empty(tmp_path: Path) -> None:
    assert gitleaks_runner._run_python_secret_scanner(tmp_path / "gone") == []


def test_semgrep_config_error_is_logged_not_silent(monkeypatch, tmp_path: Path, caplog) -> None:
    # A renamed registry pack (HTTP 404) makes Semgrep exit 7 with no results; that must
    # surface as a warning instead of looking like "no findings".
    err = {"level": "error", "message": "Failed to download configuration from https://semgrep.dev/c/p/x HTTP 404."}
    _patch_semgrep(monkeypatch, json.dumps({"results": [], "errors": [err]}))
    with caplog.at_level("WARNING", logger=semgrep_runner.log.name):
        assert semgrep_runner.run_semgrep(tmp_path) == []
    assert "HTTP 404" in caplog.text


def test_semgrep_configs_avoid_known_dead_packs() -> None:
    # p/owasp-top-10 was 404 on the registry (correct id: p/owasp-top-ten) and silently
    # zeroed every Semgrep result in the benchmark.
    assert "p/owasp-top-10" not in semgrep_runner._SEMGREP_CONFIGS
    assert "p/owasp-top-ten" in semgrep_runner._SEMGREP_CONFIGS


def test_semgrep_is_pinned_to_the_scanned_folder(monkeypatch, tmp_path: Path) -> None:
    """Without --project-root Semgrep wanders through the user's profile for minutes on non-git folders."""
    seen = {}
    monkeypatch.setattr(semgrep_runner, "_find_tool", lambda name: "semgrep")

    def fake_run(cmd, timeout_s=None, **kwargs):
        seen["cmd"] = list(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(semgrep_runner, "_run_bounded", fake_run)
    semgrep_runner.run_semgrep(tmp_path)
    cmd = seen["cmd"]
    assert cmd[cmd.index("--project-root") + 1] == str(tmp_path)
    assert "--metrics=off" in cmd
    assert cmd[-1] == str(tmp_path)
