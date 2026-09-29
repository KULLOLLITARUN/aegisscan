"""Tests for V10 Interactive Web Server.

Covers:
  - CLI parser arguments (--server, --port)
  - AegisScanRequestHandler GET / dashboard template
  - AegisScanRequestHandler GET /api/history JSON response
  - AegisScanRequestHandler POST /api/scan on-demand execution
"""
from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from main import _build_parser
from scanner.server.app import AegisScanRequestHandler


class DummyServer:
    pass


def _create_mock_request_handler(
    method: str, path: str, body: dict | None = None
) -> AegisScanRequestHandler:
    handler = AegisScanRequestHandler.__new__(AegisScanRequestHandler)
    handler.command = method
    handler.path = path
    handler.requestline = f"{method} {path} HTTP/1.1"
    handler.client_address = ("127.0.0.1", 12345)
    handler.server = DummyServer()

    if body is not None:
        body_bytes = json.dumps(body).encode("utf-8")
        handler.headers = {"Content-Length": str(len(body_bytes))}
        handler.rfile = BytesIO(body_bytes)
    else:
        handler.headers = {}
        handler.rfile = BytesIO(b"")

    handler.wfile = BytesIO()
    handler.send_response = MagicMock()
    handler.send_header = MagicMock()
    handler.end_headers = MagicMock()
    handler.send_error = MagicMock()
    return handler


def test_cli_parser_supports_server_flags() -> None:
    parser = _build_parser()
    args = parser.parse_args(["--server", "--port", "9090"])
    assert args.server is True
    assert args.port == 9090


def _use_dist(monkeypatch, dist: Path) -> None:
    import scanner.server.app as app

    monkeypatch.setattr(app, "_DIST_DIR", dist)
    monkeypatch.setattr(app, "_INDEX_HTML", dist / "index.html")


def test_server_dashboard_route_serves_built_ui(tmp_path: Path, monkeypatch) -> None:
    """Hermetic: the real dist/ is gitignored, so a fresh clone / CI has none."""
    (tmp_path / "index.html").write_text("<title>AegisScan - Command Deck</title>", encoding="utf-8")
    _use_dist(monkeypatch, tmp_path)
    handler = _create_mock_request_handler("GET", "/")
    handler.do_GET()
    handler.send_response.assert_called_with(200)
    output = handler.wfile.getvalue().decode("utf-8")
    assert "AegisScan" in output
    assert "Command Deck" in output


def test_server_dashboard_falls_back_to_basic_page_without_build(tmp_path: Path, monkeypatch) -> None:
    _use_dist(monkeypatch, tmp_path / "missing-dist")
    handler = _create_mock_request_handler("GET", "/")
    handler.do_GET()
    handler.send_response.assert_called_with(200)
    assert "AegisScan" in handler.wfile.getvalue().decode("utf-8")


def test_ui_build_hint_only_when_build_is_missing(tmp_path: Path, monkeypatch) -> None:
    import scanner.server.app as app

    _use_dist(monkeypatch, tmp_path / "missing-dist")
    hint = app._ui_build_hint()
    assert hint is not None and "npm ci" in hint and "npm run build" in hint
    (tmp_path / "index.html").write_text("<html></html>", encoding="utf-8")
    _use_dist(monkeypatch, tmp_path)
    assert app._ui_build_hint() is None


def test_run_server_prints_build_hint_when_ui_missing(tmp_path: Path, monkeypatch, capsys) -> None:
    import scanner.server.app as app

    class _StubServer:
        def __init__(self, *_a, **_k) -> None:
            pass

        def serve_forever(self) -> None:
            raise KeyboardInterrupt

        def server_close(self) -> None:
            pass

    monkeypatch.setattr(app, "HTTPServer", _StubServer)
    _use_dist(monkeypatch, tmp_path / "missing-dist")
    app.run_server(port=0)
    assert "npm run build" in capsys.readouterr().out
    (tmp_path / "index.html").write_text("<html></html>", encoding="utf-8")
    _use_dist(monkeypatch, tmp_path)
    app.run_server(port=0)
    assert "npm run build" not in capsys.readouterr().out


def test_server_history_api_route() -> None:
    handler = _create_mock_request_handler("GET", "/api/history")
    handler.do_GET()
    handler.send_response.assert_called_with(200)
    output = handler.wfile.getvalue().decode("utf-8")
    parsed = json.loads(output)
    assert isinstance(parsed, list)


def test_server_scan_api_route(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_ALLOWED_ROOTS", str(tmp_path))
    handler = _create_mock_request_handler(
        "POST", "/api/scan", body={"path": str(tmp_path), "static_only": True}
    )
    handler.do_POST()
    handler.send_response.assert_called_with(200)
    output = handler.wfile.getvalue().decode("utf-8")
    parsed = json.loads(output)
    assert "scan_id" in parsed
    assert "security_score" in parsed


def test_scan_rejects_path_outside_allowed_roots(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("AEGISSCAN_ALLOWED_ROOTS", raising=False)
    handler = _create_mock_request_handler("POST", "/api/scan", body={"path": str(tmp_path)})
    handler.do_POST()
    handler.send_response.assert_called_with(403)


def test_scan_rejects_parent_traversal(monkeypatch) -> None:
    monkeypatch.delenv("AEGISSCAN_ALLOWED_ROOTS", raising=False)
    handler = _create_mock_request_handler("POST", "/api/scan", body={"path": "../../.."})
    handler.do_POST()
    handler.send_response.assert_called_with(403)


@pytest.mark.parametrize("header,value", [("Origin", "https://evil.example"), ("Host", "evil.example:8000")])
def test_api_rejects_foreign_origin_or_host(header: str, value: str) -> None:
    handler = _create_mock_request_handler("GET", "/api/history")
    handler.headers = {header: value}
    handler.do_GET()
    handler.send_response.assert_called_with(403)


def test_api_sends_no_cors_wildcard() -> None:
    handler = _create_mock_request_handler("GET", "/api/history")
    handler.do_GET()
    sent = [c.args[0] for c in handler.send_header.call_args_list]
    assert "Access-Control-Allow-Origin" not in sent
