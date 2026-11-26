"""End-to-end: start the real local server and talk to it over real sockets.

Regression for "Mark false positive did nothing": a single-threaded server stayed stuck on an idle
browser connection, so the triage POST queued behind it and never ran.
"""
from __future__ import annotations

import http.client
import json
import socket
import threading
import time

import pytest

from scanner.server import app


@pytest.fixture
def live_server(monkeypatch):
    monkeypatch.delenv("AEGISSCAN_MODE", raising=False)
    monkeypatch.delenv("AEGISSCAN_ACCESS_TOKEN", raising=False)
    created = []

    class Spy(app._ExclusiveThreadingHTTPServer):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            created.append(self)

    monkeypatch.setattr(app, "_ExclusiveThreadingHTTPServer", Spy)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    thread = threading.Thread(target=app.run_server, args=(port,), daemon=True)
    thread.start()
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            break
        except OSError:
            time.sleep(0.05)
    else:
        pytest.fail("server did not start")
    yield port
    created[0].shutdown()
    created[0].server_close()


def _post_triage(port: int, status: str | None) -> dict:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    body = json.dumps({"target": "c:/e2e-proj", "key": "a.py|rule|msg|abc", "status": status})
    conn.request("POST", "/api/triage", body, {"Content-Type": "application/json"})
    resp = conn.getresponse()
    assert resp.status == 200
    return json.loads(resp.read())


def test_triage_works_while_idle_browser_connections_are_open(live_server) -> None:
    port = live_server
    # Like Chrome's speculative sockets: connected, never send a request.
    idle = [socket.create_connection(("127.0.0.1", port), timeout=5) for _ in range(6)]
    try:
        assert _post_triage(port, "false_positive") == {"a.py|rule|msg|abc": "false_positive"}
        assert _post_triage(port, None) == {}
    finally:
        for s in idle:
            s.close()
