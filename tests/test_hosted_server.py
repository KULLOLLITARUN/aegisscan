"""Hosted-mode behaviour of the web server (AEGISSCAN_MODE=hosted)."""
from __future__ import annotations

import json
import logging
import os
import threading
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scanner.models.finding import Finding, Severity
from scanner.models.scan import ScanResult
from scanner.server import hosted
from scanner.server.app import AegisScanRequestHandler, _SSELogHandler

TOKEN = "t" * 24


class _Dummy:
    pass


def _handler(method: str, path: str, body: dict | None = None, headers: dict | None = None):
    h = AegisScanRequestHandler.__new__(AegisScanRequestHandler)
    h.command, h.path = method, path
    h.requestline = f"{method} {path} HTTP/1.1"
    h.client_address = ("203.0.113.9", 4000)
    h.server = _Dummy()
    raw = json.dumps(body).encode() if body is not None else b""
    h.headers = {"Content-Length": str(len(raw)), **(headers or {})}
    h.rfile = BytesIO(raw)
    h.wfile = BytesIO()
    h.send_response = MagicMock()
    h.send_header = MagicMock()
    h.end_headers = MagicMock()
    h.send_error = MagicMock()
    return h


def _auth(token: str = TOKEN) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _json(h) -> object:
    return json.loads(h.wfile.getvalue().decode())


@pytest.fixture(autouse=True)
def hosted_env(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGISSCAN_MODE", "hosted")
    monkeypatch.setenv("AEGISSCAN_ACCESS_TOKEN", TOKEN)
    monkeypatch.setenv("AEGISSCAN_WORKSPACE_DIR", str(tmp_path / "ws"))
    monkeypatch.delenv("AEGISSCAN_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("RENDER_EXTERNAL_HOSTNAME", raising=False)
    monkeypatch.delenv("AEGISSCAN_HOSTED_LLM", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setattr(hosted, "_scan_limiter", hosted.RateLimiter(100, 60))
    monkeypatch.setattr(hosted, "_slots", hosted.ScanSlots(2))


def _workspace_with_code(files: dict[str, str]) -> tuple[str, Path]:
    wid, ws = hosted.new_workspace()
    for name, text in files.items():
        f = hosted.code_dir(ws) / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")
    hosted.write_label(ws, "my-app")
    return wid, ws


def _result_for(code: Path, n: int = 1) -> ScanResult:
    findings = [
        Finding(
            file_path=code / "a.py", issue_type="SQL injection", category="injection",
            severity=Severity.HIGH, confidence=0.9, line_start=1, line_end=1,
            evidence="x", explanation="y", rule_source="bandit",
        )
        for _ in range(n)
    ]
    return ScanResult(target_path=code, findings=findings, files_analyzed=1, security_score=80.0)


# ------------------------------------------------------------------ config and startup
def test_hosted_refuses_to_start_without_a_strong_token(monkeypatch) -> None:
    monkeypatch.delenv("AEGISSCAN_ACCESS_TOKEN")
    assert hosted.startup_errors()
    monkeypatch.setenv("AEGISSCAN_ACCESS_TOKEN", "short")
    assert hosted.startup_errors()
    monkeypatch.setenv("AEGISSCAN_ACCESS_TOKEN", TOKEN)
    assert hosted.startup_errors() == []


def test_local_mode_has_no_startup_errors(monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_MODE", "local")
    monkeypatch.delenv("AEGISSCAN_ACCESS_TOKEN")
    assert hosted.startup_errors() == []


def test_config_endpoint_needs_no_token_and_describes_hosted_mode() -> None:
    h = _handler("GET", "/api/config")
    h.do_GET()
    cfg = _json(h)
    assert cfg["mode"] == "hosted" and cfg["auth_required"] is True
    assert cfg["features"] == {"path": False, "upload": True, "git": True, "llm": False, "history": False}
    assert cfg["limits"]["max_upload_mb"] == 50


def test_config_endpoint_in_local_mode(monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_MODE", "local")
    h = _handler("GET", "/api/config")
    h.do_GET()
    cfg = _json(h)
    assert cfg["mode"] == "local" and cfg["features"]["path"] is True and cfg["auth_required"] is False


def test_health_endpoint_is_open() -> None:
    h = _handler("GET", "/api/health")
    h.do_GET()
    assert _json(h) == {"ok": True}


# ------------------------------------------------------------------ auth
@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer nope"}, {"Authorization": TOKEN}, {"Authorization": "Basic " + TOKEN}])
def test_api_calls_need_the_access_token(headers) -> None:
    for method, path in (("POST", "/api/scan"), ("POST", "/api/scan/stream"), ("GET", "/api/history")):
        h = _handler(method, path, body={} if method == "POST" else None, headers=headers)
        (h.do_POST if method == "POST" else h.do_GET)()
        h.send_response.assert_called_with(401)


def test_history_is_empty_and_never_touches_the_database(monkeypatch) -> None:
    def boom(*_a, **_k):
        raise AssertionError("history DB must not be used in hosted mode")

    monkeypatch.setattr("scanner.storage.history.ScanHistoryDB", boom)
    h = _handler("GET", "/api/history", headers=_auth())
    h.do_GET()
    assert _json(h) == []


# ------------------------------------------------------------------ host and origin
def test_unlisted_host_is_rejected(monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_ALLOWED_HOSTS", "scan.example.com")
    h = _handler("GET", "/api/config", headers={"Host": "evil.example"})
    h.do_GET()
    h.send_response.assert_called_with(403)


def test_listed_host_and_render_hostname_are_accepted(monkeypatch) -> None:
    monkeypatch.setenv("RENDER_EXTERNAL_HOSTNAME", "aegis.onrender.com")
    h = _handler("GET", "/api/config", headers={"Host": "aegis.onrender.com"})
    h.do_GET()
    h.send_response.assert_called_with(200)


def test_cross_site_origin_is_rejected() -> None:
    h = _handler("POST", "/api/scan", body={}, headers={**_auth(), "Host": "scan.example.com", "Origin": "https://evil.example"})
    h.do_POST()
    h.send_response.assert_called_with(403)


def test_same_site_origin_is_accepted() -> None:
    h = _handler("GET", "/api/config", headers={"Host": "scan.example.com", "Origin": "https://scan.example.com"})
    h.do_GET()
    h.send_response.assert_called_with(200)


# ------------------------------------------------------------------ sources
def test_server_paths_are_never_scanned_in_hosted_mode(tmp_path) -> None:
    h = _handler("POST", "/api/scan", body={"path": str(tmp_path)}, headers=_auth())
    h.do_POST()
    h.send_response.assert_called_with(400)


def test_unknown_or_malformed_upload_id_is_404() -> None:
    for bad in ("0" * 32, "../../etc", "x"):
        h = _handler("POST", "/api/scan", body={"upload_id": bad}, headers=_auth())
        h.do_POST()
        h.send_response.assert_called_with(404)


# ------------------------------------------------------------------ scanning an upload
def test_scan_forces_static_only_ignores_user_key_and_skips_history(monkeypatch) -> None:
    wid, ws = _workspace_with_code({"a.py": "x = 1\n"})
    seen: dict = {}

    def fake_run(**kwargs):
        seen.update(kwargs)
        return _result_for(kwargs["path"]), None, None

    monkeypatch.setattr("main.run", fake_run)  # importing main also runs load_dotenv(), so snapshot after
    key_before = os.environ.get("GROQ_API_KEY")
    body = {"upload_id": wid, "static_only": False, "deep": True, "generate_patches": True,
            "privacy": "standard", "api_key": "gsk_user_supplied"}
    h = _handler("POST", "/api/scan", body=body, headers=_auth())
    h.do_POST()

    h.send_response.assert_called_with(200)
    assert seen["static_only"] is True and seen["deep"] is False and seen["generate_patches"] is False
    assert seen["privacy"] == "strict" and seen["record_history"] is False
    assert seen["path"] == hosted.code_dir(ws)
    key_unchanged = os.environ.get("GROQ_API_KEY") == key_before
    assert key_unchanged  # a user's key must never reach the shared process (values are never printed)


def test_result_carries_no_server_paths(monkeypatch) -> None:
    wid, ws = _workspace_with_code({"a.py": "x = 1\n"})
    monkeypatch.setattr("main.run", lambda **kw: (_result_for(kw["path"]), None, None))
    h = _handler("POST", "/api/scan", body={"upload_id": wid}, headers=_auth())
    h.do_POST()
    text = h.wfile.getvalue().decode()
    data = json.loads(text)
    assert data["target_path"] == "my-app"
    assert data["findings"][0]["file_path"] == "a.py"
    assert str(ws) not in text and ws.as_posix() not in text and str(hosted.workspace_root()) not in text


def test_stream_scrubs_paths_in_progress_logs_and_errors(monkeypatch) -> None:
    wid, ws = _workspace_with_code({"a.py": "x = 1\n"})
    code = hosted.code_dir(ws)

    def fake_run(**kwargs):
        kwargs["progress"]("Static analysis", 40, f"scanning {code}")
        logging.getLogger("scanner.test").info("Bandit: 1 findings in %s", code)
        return _result_for(kwargs["path"]), None, None

    monkeypatch.setattr("main.run", fake_run)
    h = _handler("POST", "/api/scan/stream", body={"upload_id": wid}, headers=_auth())
    h.do_POST()
    text = h.wfile.getvalue().decode()
    assert "event: complete" in text and "event: log" in text
    assert str(code) not in text and code.as_posix() not in text and "my-app" in text

    def failing_run(**kwargs):
        raise RuntimeError(f"cannot read {code}")

    monkeypatch.setattr("main.run", failing_run)
    h = _handler("POST", "/api/scan/stream", body={"upload_id": wid}, headers=_auth())
    h.do_POST()
    text = h.wfile.getvalue().decode()
    assert "event: error" in text and str(code) not in text


# ------------------------------------------------------------------ limits
def test_rate_limit_returns_429(monkeypatch) -> None:
    monkeypatch.setattr(hosted, "_scan_limiter", hosted.RateLimiter(1, 60))
    wid, _ = _workspace_with_code({"a.py": "x = 1\n"})
    monkeypatch.setattr("main.run", lambda **kw: (_result_for(kw["path"]), None, None))
    first = _handler("POST", "/api/scan", body={"upload_id": wid}, headers=_auth())
    first.do_POST()
    first.send_response.assert_called_with(200)
    second = _handler("POST", "/api/scan", body={"upload_id": wid}, headers=_auth())
    second.do_POST()
    second.send_response.assert_called_with(429)


def test_rate_limiter_window_slides() -> None:
    now = [0.0]
    rl = hosted.RateLimiter(2, 10, clock=lambda: now[0])
    assert rl.allow("a") and rl.allow("a") and not rl.allow("a")
    assert rl.allow("b")  # separate clients are independent
    now[0] = 11.0
    assert rl.allow("a")


def test_busy_server_returns_503_and_slot_is_released(monkeypatch) -> None:
    slots = hosted.ScanSlots(1)
    monkeypatch.setattr(hosted, "_slots", slots)
    wid, _ = _workspace_with_code({"a.py": "x = 1\n"})
    assert slots.try_acquire()  # another scan is running
    h = _handler("POST", "/api/scan", body={"upload_id": wid}, headers=_auth())
    h.do_POST()
    h.send_response.assert_called_with(503)
    slots.release()

    monkeypatch.setattr("main.run", lambda **kw: (_result_for(kw["path"]), None, None))
    h = _handler("POST", "/api/scan", body={"upload_id": wid}, headers=_auth())
    h.do_POST()
    h.send_response.assert_called_with(200)
    assert slots.try_acquire()  # the finished scan gave its slot back
    slots.release()


def test_timeout_returns_504_and_slot_frees_only_when_worker_ends(monkeypatch) -> None:
    slots = hosted.ScanSlots(1)
    monkeypatch.setattr(hosted, "_slots", slots)
    monkeypatch.setenv("AEGISSCAN_SCAN_TIMEOUT_S", "1")
    wid, _ = _workspace_with_code({"a.py": "x = 1\n"})
    release_worker = threading.Event()

    def slow_run(**kwargs):
        release_worker.wait(10)
        return _result_for(kwargs["path"]), None, None

    monkeypatch.setattr("main.run", slow_run)
    h = _handler("POST", "/api/scan", body={"upload_id": wid}, headers=_auth())
    h.do_POST()
    h.send_response.assert_called_with(504)
    assert not slots.try_acquire()  # the runaway scan still holds its slot
    release_worker.set()
    for _ in range(50):
        if slots.try_acquire():
            slots.release()
            break
        threading.Event().wait(0.1)
    else:
        pytest.fail("slot was never released after the worker finished")


def test_run_with_timeout_runs_on_finish_after_the_worker_ends() -> None:
    done = threading.Event()
    gate = threading.Event()

    def fn():
        gate.wait(5)
        return 1

    with pytest.raises(hosted.ScanTimeout):
        hosted.run_with_timeout(fn, 0.1, on_finish=done.set)
    assert not done.is_set()
    gate.set()
    assert done.wait(5)


# ------------------------------------------------------------------ log isolation and scrubbing
def test_log_handler_only_forwards_its_own_thread() -> None:
    got: list = []
    handler = _SSELogHandler(lambda ev, data: got.append(data["message"]), thread_id=threading.get_ident())
    logger = logging.getLogger("hosted-isolation-test")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    try:
        logger.info("mine")
        t = threading.Thread(target=lambda: logger.info("someone else"))
        t.start()
        t.join()
    finally:
        logger.removeHandler(handler)
    assert got == ["mine"]


def test_sanitize_text_and_result(tmp_path) -> None:
    root = tmp_path / "w" / "code"
    root.mkdir(parents=True)
    assert hosted.sanitize_text(f"in {root} and {root.as_posix()}/x", root, "my-app") == "in my-app and my-app/x"
    result = _result_for(root)
    hosted.sanitize_result(result, root, "my-app")
    assert result.target_path == Path("my-app") and result.findings[0].file_path == Path("a.py")


def test_stream_keeps_the_connection_busy_during_a_quiet_scan(monkeypatch) -> None:
    """Tunnels and proxies cut connections that send nothing for ~100 s, and Semgrep can be silent
    that long. The stream must send keep-alive comments, still deliver the result, then go quiet."""
    import time

    monkeypatch.setenv("AEGISSCAN_SSE_KEEPALIVE_S", "0.3")
    wid, _ = _workspace_with_code({"a.py": "x = 1\n"})

    def quiet_run(**kwargs):
        time.sleep(1.3)  # no progress events at all
        return _result_for(kwargs["path"]), None, None

    monkeypatch.setattr("main.run", quiet_run)
    h = _handler("POST", "/api/scan/stream", body={"upload_id": wid}, headers=_auth())
    h.do_POST()
    text = h.wfile.getvalue().decode()
    assert text.count(": keepalive") >= 2
    assert "event: complete" in text

    size = len(h.wfile.getvalue())
    time.sleep(0.9)
    assert len(h.wfile.getvalue()) == size  # the heartbeat stopped when the stream closed


def test_delete_workspace_removes_read_only_files() -> None:
    """git marks pack files read-only; a plain rmtree(ignore_errors=True) leaves them behind on Windows."""
    import os
    import stat

    _, ws = hosted.new_workspace()
    pack = hosted.code_dir(ws) / ".git" / "objects" / "pack" / "pack-1.pack"
    pack.parent.mkdir(parents=True)
    pack.write_text("data", encoding="utf-8")
    os.chmod(pack, stat.S_IREAD)
    hosted.delete_workspace(ws)
    assert not ws.exists()


def test_workspace_sweep_removes_only_old_workspaces() -> None:
    import time

    old_id, old = hosted.new_workspace()
    new_id, _ = hosted.new_workspace()
    past = time.time() - 3600
    os.utime(old, (past, past))
    assert hosted.sweep(ttl_seconds=1800) == 1
    assert hosted.get_workspace(old_id) is None and hosted.get_workspace(new_id) is not None
