"""Server side of the UI work: kept results, triage, export, cancelling a scan.

All storage goes to the per-test data folder (conftest sets AEGISSCAN_HISTORY_DB to a temp file).
"""
from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import scanner.server.app as app
from scanner.models.finding import Finding, Severity
from scanner.models.scan import ScanResult
from scanner.server.app import AegisScanRequestHandler, ScanCancelled, _send_progress
from scanner.storage import results as results_store
from scanner.storage import triage as triage_store


def _result(scan_id: str = "11111111-2222-3333-4444-555555555555", n: int = 2) -> ScanResult:
    findings = [
        Finding(
            file_path=Path("/proj/app.py"), issue_type=f"Issue {i} <script>", category="injection",
            severity=Severity.HIGH, confidence=0.8, line_start=10 + i, line_end=10 + i,
            evidence="os.system(cmd)", explanation="why", rule_source="bandit",
        )
        for i in range(n)
    ]
    return ScanResult(scan_id=scan_id, target_path=Path("/proj"), findings=findings, security_score=61.0)


class _Server:
    pass


def _handler(method: str, path: str, body: bytes | None = None) -> AegisScanRequestHandler:
    h = AegisScanRequestHandler.__new__(AegisScanRequestHandler)
    h.command, h.path, h.requestline = method, path, f"{method} {path} HTTP/1.1"
    h.client_address = ("127.0.0.1", 1)
    h.server = _Server()
    h.headers = {"Content-Length": str(len(body))} if body is not None else {}
    h.rfile = BytesIO(body or b"")
    h.wfile = BytesIO()
    h.send_response = MagicMock()
    h.send_header = MagicMock()
    h.end_headers = MagicMock()
    h.send_error = MagicMock()
    return h


def _status(h) -> int:
    return int(h.send_response.call_args[0][0])


def _headers(h) -> dict:
    return {c[0][0]: c[0][1] for c in h.send_header.call_args_list}


# ------------------------------------------------------------------ kept results
def test_results_are_kept_loaded_and_pruned(monkeypatch) -> None:
    import os
    monkeypatch.setattr(results_store, "KEEP_RESULTS", 3)
    ids = [f"0000000{i}-aaaa-bbbb-cccc-dddddddddddd" for i in range(5)]
    for i, sid in enumerate(ids):
        results_store.save_result(_result(sid))
        # explicit, increasing times: fast file systems can give two writes the same mtime
        path = results_store.results_dir() / f"{sid}.json"
        if path.exists():
            os.utime(path, (1_000_000 + i, 1_000_000 + i))
    # pruning runs on every save; one more save of the newest leaves the three newest
    results_store.save_result(_result(ids[-1]))
    assert results_store.kept_ids() == set(ids[-3:])
    assert json.loads(results_store.latest_result())["scan_id"] == ids[-1]
    assert results_store.load_result(ids[0]) is None


@pytest.mark.parametrize("bad", ["../secret", "..\\x", "abc", "x" * 80, "", "11111111-2222/../../etc"])
def test_result_ids_that_could_escape_the_folder_are_refused(bad) -> None:
    assert results_store.load_result(bad) is None
    h = _handler("GET", f"/api/scan/{bad}")
    h.do_GET()
    assert _status(h) == 404


def test_last_and_scan_endpoints(monkeypatch) -> None:
    h = _handler("GET", "/api/last")
    h.do_GET()
    assert _status(h) == 404                         # nothing kept yet
    results_store.save_result(_result())
    h = _handler("GET", "/api/last")
    h.do_GET()
    assert _status(h) == 200 and json.loads(h.wfile.getvalue())["scan_id"].startswith("11111111")
    h = _handler("GET", "/api/scan/11111111-2222-3333-4444-555555555555")
    h.do_GET()
    assert _status(h) == 200 and len(json.loads(h.wfile.getvalue())["findings"]) == 2


def test_history_marks_rows_that_kept_their_details(monkeypatch) -> None:
    kept = _result("aaaaaaaa-0000-0000-0000-000000000001")
    results_store.save_result(kept)
    rows = [{"scan_id": kept.scan_id}, {"scan_id": "bbbbbbbb-0000-0000-0000-000000000002"}]
    monkeypatch.setattr("scanner.storage.history.ScanHistoryDB.get_history", lambda self, limit=20: rows)
    h = _handler("GET", "/api/history?limit=5")
    h.do_GET()
    data = json.loads(h.wfile.getvalue())
    assert [r["has_result"] for r in data] == [True, False]


def test_hosted_mode_keeps_and_serves_nothing(monkeypatch) -> None:
    results_store.save_result(_result())
    monkeypatch.setattr(app.hosted, "is_hosted", lambda: True)
    for path in ("/api/last", "/api/scan/11111111-2222-3333-4444-555555555555", "/api/triage?target=x"):
        h = _handler("GET", path)
        h._handle_local_state_get(path.split("?")[0], path.partition("?")[2])
        assert _status(h) == 404


# ------------------------------------------------------------------ triage
def test_triage_store_round_trip_and_validation() -> None:
    triage_store.set_triage("C:\\Proj\\", "app.py|bandit|Issue|injection", "false_positive")
    assert triage_store.get_triage("c:/proj") == {"app.py|bandit|Issue|injection": "false_positive"}
    triage_store.set_triage("c:/proj", "app.py|bandit|Issue|injection", None)
    assert triage_store.get_triage("c:/proj") == {}
    with pytest.raises(ValueError):
        triage_store.set_triage("c:/proj", "k", "ignored")
    with pytest.raises(ValueError):
        triage_store.set_triage("", "k", "accepted")
    with pytest.raises(ValueError):
        triage_store.set_triage("c:/proj", "k" * 700, "accepted")


def test_triage_endpoints() -> None:
    body = json.dumps({"target": "/proj", "key": "a|b|c|d", "status": "accepted"}).encode()
    h = _handler("POST", "/api/triage", body)
    h.do_POST()
    assert json.loads(h.wfile.getvalue()) == {"a|b|c|d": "accepted"}
    h = _handler("GET", "/api/triage?target=/proj")
    h.do_GET()
    assert json.loads(h.wfile.getvalue()) == {"a|b|c|d": "accepted"}
    bad = json.dumps({"target": "/proj", "key": "a", "status": "nope"}).encode()
    h = _handler("POST", "/api/triage", bad)
    h.do_POST()
    assert _status(h) == 400
    wrong_types = json.dumps({"target": 5, "key": "a", "status": None}).encode()
    h = _handler("POST", "/api/triage", wrong_types)
    h.do_POST()
    assert _status(h) == 400


# ------------------------------------------------------------------ export
@pytest.mark.parametrize("fmt, ctype, needle", [
    ("html", "text/html", b"<html"),
    ("sarif", "application/sarif+json", b'"version"'),
    ("json", "application/json", b'"scan_id"'),
])
def test_export_formats(fmt, ctype, needle) -> None:
    body = _result().model_dump_json().encode()
    h = _handler("POST", f"/api/export?format={fmt}", body)
    h.do_POST()
    assert _status(h) == 200
    hdr = _headers(h)
    assert hdr["Content-Type"].startswith(ctype)
    assert hdr["Content-Disposition"] == f'attachment; filename="aegisscan-11111111.{fmt}"'
    out = h.wfile.getvalue()
    assert needle in out.lower() if fmt == "html" else needle in out


def test_export_escapes_values_from_the_body() -> None:
    h = _handler("POST", "/api/export?format=html", _result().model_dump_json().encode())
    h.do_POST()
    html = h.wfile.getvalue().decode()
    assert "Issue 0 <script>" not in html and "Issue 0 &lt;script&gt;" in html


@pytest.mark.parametrize("path, body, status", [
    ("/api/export?format=pdf", b"{}", 400),
    ("/api/export?format=html", b"{not json", 400),
    ("/api/export?format=html", b'{"findings": "nope"}', 400),
    ("/api/export?format=html", b"", 411),
])
def test_export_rejects_bad_requests(path, body, status) -> None:
    h = _handler("POST", path, body)
    h.do_POST()
    assert _status(h) == status


# ------------------------------------------------------------------ cancel
def test_progress_stops_the_scan_once_the_browser_is_gone() -> None:
    sent = []

    def sse(event, data):
        sent.append(event)
    sse.gone = lambda: False
    _send_progress(sse, {"phase": "x"})
    sse.gone = lambda: True
    with pytest.raises(ScanCancelled):
        _send_progress(sse, {"phase": "y"})
    assert sent == ["progress", "progress"]


def test_scan_cancelled_gets_past_main_runs_callback_guard() -> None:
    """main.run swallows ordinary exceptions from progress callbacks; a cancel must still stop it."""
    from main import run

    def cancel(*_a, **_k):
        raise ScanCancelled()
    target = Path(__file__).resolve().parents[1] / "examples" / "clean_python"
    with pytest.raises(ScanCancelled):
        run(path=target, static_only=True, progress=cancel, record_history=False)


def test_a_cancelled_stream_is_logged_not_reported_as_an_error(monkeypatch, tmp_path, caplog) -> None:
    import main
    monkeypatch.setattr(main, "run", lambda **_k: (_ for _ in ()).throw(ScanCancelled()))
    h = _handler("POST", "/api/scan/stream")
    fake = _FakeSse()
    h._open_sse = lambda: fake
    with caplog.at_level("INFO"):
        h._local_stream(tmp_path, {"static_only": True, "deep": False, "generate_patches": False, "privacy": "standard"})
    assert "Scan stopped" in caplog.text
    assert "error" not in fake.events and "complete" not in fake.events


def test_a_queued_stream_tells_the_browser_it_is_waiting_then_runs(monkeypatch, tmp_path) -> None:
    import threading
    import main
    from scanner.server import app as server_app
    monkeypatch.setattr(main, "run", lambda **_k: (_ for _ in ()).throw(RuntimeError("ran")))
    h = _handler("POST", "/api/scan/stream")
    fake = _FakeSse()
    h._open_sse = lambda: fake
    settings = {"static_only": True, "deep": False, "generate_patches": False, "privacy": "standard"}
    server_app._LOCAL_SCAN_LOCK.acquire()  # another scan is running
    worker = threading.Thread(target=h._local_stream, args=(tmp_path, settings))
    worker.start()
    try:
        for _ in range(100):
            if fake.data:
                break
            threading.Event().wait(0.05)
        assert fake.data and fake.data[0][0] == "progress"
        assert "Waiting for the previous scan" in fake.data[0][1]["phase"]
    finally:
        server_app._LOCAL_SCAN_LOCK.release()
        worker.join(5)
    assert not worker.is_alive()
    assert "error" in fake.events  # it went on to run once the lock was free
    assert server_app._LOCAL_SCAN_LOCK.acquire(blocking=False)  # and released it again
    server_app._LOCAL_SCAN_LOCK.release()


def test_a_stream_cancelled_while_waiting_never_starts(monkeypatch, tmp_path) -> None:
    from scanner.server import app as server_app
    h = _handler("POST", "/api/scan/stream")
    fake = _FakeSse()
    fake.gone = lambda: True
    h._open_sse = lambda: fake
    called = []
    import main
    monkeypatch.setattr(main, "run", lambda **_k: called.append(1))
    server_app._LOCAL_SCAN_LOCK.acquire()
    try:
        h._local_stream(tmp_path, {"static_only": True, "deep": False, "generate_patches": False, "privacy": "standard"})
    finally:
        server_app._LOCAL_SCAN_LOCK.release()
    assert not called
    assert server_app._LOCAL_SCAN_LOCK.acquire(blocking=False)
    server_app._LOCAL_SCAN_LOCK.release()


class _FakeSse:
    def __init__(self) -> None:
        self.events: list[str] = []
        self.data: list[tuple[str, dict]] = []

    def __call__(self, event, data) -> None:
        self.events.append(event)
        self.data.append((event, data))

    def gone(self) -> bool:
        return False

    def close(self) -> None:
        pass


def test_sarif_export_of_a_hosted_result_with_a_label_target() -> None:
    """Found by these tests: generate_sarif crashed on a relative target (hosted results use a label)."""
    hosted_like = _result().model_copy(update={"target_path": Path("owner-repo")})
    h = _handler("POST", "/api/export?format=sarif", hosted_like.model_dump_json().encode())
    h.do_POST()
    assert _status(h) == 200
    sarif = json.loads(h.wfile.getvalue())
    assert "originalUriBaseIds" not in sarif["runs"][0]
