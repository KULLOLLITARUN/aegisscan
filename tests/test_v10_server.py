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

import pytest
from unittest.mock import MagicMock

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


def test_server_dashboard_route() -> None:
    handler = _create_mock_request_handler("GET", "/")
    handler.do_GET()
    handler.send_response.assert_called_with(200)
    output = handler.wfile.getvalue().decode("utf-8")
    assert "AegisScan" in output
    assert "Command Deck" in output


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
