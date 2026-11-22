"""
AegisScan Web Server — Production

Serves the React production bundle and REST/SSE API endpoints.
  GET  /               → React SPA (dist/index.html)
  GET  /assets/*       → Vite build static assets
  GET  /api/history    → JSON scan history from SQLite
  GET  /api/scan/stream→ SSE live scan progress stream (events: progress, log, complete, error)
  POST /api/scan       → Synchronous scan (JSON response)
"""
from __future__ import annotations

import json
import logging
import mimetypes
import os
import socket
import sys
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger(__name__)

# React Vite build output; the source lives in <repo root>/ui and builds into this package
_DIST_DIR = Path(__file__).parent / "dist"
_INDEX_HTML = _DIST_DIR / "index.html"

_PROJECT_ROOT = Path(__file__).parent.parent.parent
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "[::1]"}


def _ui_build_hint() -> str | None:
    """How to get the React dashboard when only the basic fallback page is available.
    The build output (scanner/server/dist) is not committed; see the README."""
    if _INDEX_HTML.exists():
        return None
    return (
        "React dashboard build not found - serving the basic fallback page.\n"
        "  Build it once with: cd ui && npm ci && npm run build"
    )


def _allowed_roots() -> list[Path]:
    """Directories the server may scan: the project root plus any paths listed in
    AEGISSCAN_ALLOWED_ROOTS (os.pathsep-separated). Read per request so it can be
    changed without a restart."""
    roots = [_PROJECT_ROOT.resolve()]
    for extra in os.environ.get("AEGISSCAN_ALLOWED_ROOTS", "").split(os.pathsep):
        if extra.strip():
            roots.append(Path(extra.strip()).resolve())
    return roots


def _allow_any_path() -> bool:
    """Opt-in escape hatch: AEGISSCAN_ALLOW_ANY_PATH=1 lets the server scan any directory.
    Off by default. The Host/Origin checks still apply. Read per request."""
    return os.environ.get("AEGISSCAN_ALLOW_ANY_PATH", "").strip().lower() in ("1", "true", "yes")


def _resolve_scan_path(raw_path: str) -> Path:
    """Resolve a user-supplied scan path; raise PermissionError if it lies outside
    every allowed root (blocks scanning arbitrary directories via the API), unless
    AEGISSCAN_ALLOW_ANY_PATH is set."""
    candidate = Path(raw_path)
    target = (candidate if candidate.is_absolute() else _PROJECT_ROOT / candidate).resolve()
    if _allow_any_path():
        return target
    for root in _allowed_roots():
        if target == root or root in target.parents:
            return target
    raise PermissionError(
        f"Path is outside the allowed scan roots: {target}. "
        "Set AEGISSCAN_ALLOWED_ROOTS to permit additional directories, "
        "or AEGISSCAN_ALLOW_ANY_PATH=1 to permit any directory."
    )


def _parse_qs_bool(val: str | None, default: bool = False) -> bool:
    if val is None:
        return default
    return val.lower() in ("1", "true", "yes")


class _SSELogHandler(logging.Handler):
    """Forwards Python log records (provider failover, rate limits, tool errors —
    everything that previously only reached the server's own terminal) to the
    browser as SSE "log" events, in real time, while a scan is in flight."""

    def __init__(self, sse_fn) -> None:
        super().__init__()
        self._sse = sse_fn
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._sse("log", {
                "ts": time.strftime("%H:%M:%S"),
                "level": record.levelname.lower(),
                "logger": record.name,
                "message": self.format(record),
            })
        except Exception:
            pass  # never let a logging hiccup break the scan itself


class AegisScanRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the AegisScan web server."""

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        log.debug(format, *args)

    # ------------------------------------------------------------------ helpers
    def _send_json(self, data: Any, status: int = HTTPStatus.OK) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _request_allowed(self) -> bool:
        """Reject DNS-rebinding (non-local Host) and cross-site (foreign Origin)
        requests. The UI is served same-origin, so no CORS is needed."""
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0] if self.headers.get("Host") else ""
        if host and host.lower() not in _LOCAL_HOSTS:
            self._send_json({"error": "Forbidden host"}, status=HTTPStatus.FORBIDDEN)
            return False
        origin = self.headers.get("Origin")
        if origin:
            origin_host = (urlparse(origin).hostname or "").lower()
            if origin_host not in {"localhost", "127.0.0.1", "::1"}:
                self._send_json({"error": "Forbidden origin"}, status=HTTPStatus.FORBIDDEN)
                return False
        return True

    def _serve_static(self, path: Path) -> None:
        if not path.exists() or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        mime, _ = mimetypes.guess_type(path.name)
        body = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mime or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ------------------------------------------------------------------ GET
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        # ── Scan history ──────────────────────────────────────────────────
        if path.startswith("/api/") and not self._request_allowed():
            return

        if path == "/api/history":
            qs = parse_qs(parsed.query)
            limit = int(qs.get("limit", ["20"])[0])
            from scanner.storage.history import ScanHistoryDB
            db = ScanHistoryDB()
            self._send_json(db.get_history(limit=limit))
            return

        # ── SSE live scan stream ─────────────────────────────────────────
        if path == "/api/scan/stream":
            self._handle_sse_scan(parsed.query)
            return

        # ── Vite asset files ─────────────────────────────────────────────
        if path.startswith("/assets/"):
            self._serve_static(_DIST_DIR / path.lstrip("/"))
            return

        # ── React SPA — serve index.html for all other routes ────────────
        if _INDEX_HTML.exists():
            self._serve_static(_INDEX_HTML)
        else:
            # Fallback: legacy template
            legacy = Path(__file__).parent / "templates" / "index.html"
            if legacy.exists():
                self._serve_static(legacy)
            else:
                body = b"<h1>AegisScan - run npm run build in ui/</h1>"
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

    # ------------------------------------------------------------------ POST
    def do_POST(self) -> None:
        if self.path == "/api/scan":
            if not self._request_allowed():
                return
            self._handle_sync_scan()
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    # ------------------------------------------------------------------ SSE scan
    def _handle_sse_scan(self, query_string: str) -> None:
        qs = parse_qs(query_string)
        raw_path = qs.get("path", ["."])[0]
        try:
            target_path = _resolve_scan_path(raw_path)
        except PermissionError as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.FORBIDDEN)
            return
        static_only = _parse_qs_bool(qs.get("static_only", ["true"])[0], default=True)
        deep = _parse_qs_bool(qs.get("deep", ["false"])[0])
        generate_patches = _parse_qs_bool(qs.get("generate_patches", ["false"])[0])
        privacy = qs.get("privacy", ["standard"])[0]
        if privacy == "strict":
            static_only = True
            deep = False
            generate_patches = False
        api_key = qs.get("api_key", [""])[0]
        if api_key:
            os.environ["GROQ_API_KEY"] = api_key

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        def sse(event: str, data: Any) -> None:
            payload = f"event: {event}\ndata: {json.dumps(data)}\n\n"
            try:
                self.wfile.write(payload.encode("utf-8"))
                self.wfile.flush()
            except Exception:
                pass

        try:
            # Validate path before calling run() — run() uses sys.exit() on bad paths
            if not target_path.exists():
                sse("error", {"error": f"Path does not exist: {target_path}"})
                return
            if not target_path.is_dir():
                sse("error", {"error": f"Path is not a directory: {target_path}"})
                return

            from main import run

            def on_progress(phase: str, pct: int, detail: str = "") -> None:
                sse("progress", {
                    "phase": f"{phase}: {detail}" if detail else phase,
                    "file": "",
                    "pct": pct,
                    "found": 0,
                })

            # Scan run — attach a temporary handler so provider/tool log
            # activity (rate limits, failovers, static-tool errors) streams to
            # the browser live instead of only reaching this process's stdout.
            root_logger = logging.getLogger()
            log_handler = _SSELogHandler(sse)
            log_handler.setLevel(logging.INFO)
            prev_level = root_logger.level
            root_logger.addHandler(log_handler)
            root_logger.setLevel(min(prev_level or logging.WARNING, logging.INFO))
            try:
                result, _, _ = run(
                    path=target_path,
                    static_only=static_only,
                    deep=deep,
                    generate_patches=generate_patches,
                    privacy=privacy,
                    progress=on_progress,
                )
            finally:
                root_logger.removeHandler(log_handler)
                root_logger.setLevel(prev_level)

            sse("progress", {"phase": "Complete", "file": "", "pct": 100, "found": len(result.findings)})
            sse("complete", json.loads(result.model_dump_json()))

        except Exception as exc:
            import traceback
            log.error("SSE scan error: %s\n%s", exc, traceback.format_exc())
            sse("error", {"error": str(exc)})

    # ------------------------------------------------------------------ sync scan
    def _handle_sync_scan(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_length) if content_length > 0 else b"{}"
        try:
            payload = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            payload = {}

        try:
            target_path = _resolve_scan_path(str(payload.get("path", ".")))
        except PermissionError as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.FORBIDDEN)
            return
        static_only = bool(payload.get("static_only", True))
        generate_patches = bool(payload.get("generate_patches", False))
        deep = bool(payload.get("deep", False))
        privacy = str(payload.get("privacy", "standard"))
        if privacy == "strict":
            static_only = True
            deep = False
            generate_patches = False
        api_key = str(payload.get("api_key", "")).strip()
        if api_key:
            os.environ["GROQ_API_KEY"] = api_key

        if not target_path.exists() or not target_path.is_dir():
            self._send_json({"error": f"Invalid path: {target_path}"}, status=HTTPStatus.BAD_REQUEST)
            return
        try:
            from main import run
            result, _, _ = run(
                path=target_path,
                static_only=static_only,
                deep=deep,
                generate_patches=generate_patches,
                privacy=privacy,
            )
            self._send_json(json.loads(result.model_dump_json()))
        except Exception as exc:
            import traceback
            log.error("Sync scan error: %s\n%s", exc, traceback.format_exc())
            self._send_json({"error": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)


class _ExclusiveHTTPServer(HTTPServer):
    """HTTPServer that never shares a port with another process.

    On Windows, SO_REUSEADDR (which HTTPServer enables) lets a second server bind a port that is
    already in use, so an old server keeps answering requests while a newly started one looks
    healthy. Use SO_EXCLUSIVEADDRUSE there so a busy port fails loudly instead.
    """

    allow_reuse_address = os.name != "nt"

    def server_bind(self) -> None:
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def run_server(port: int = 8000) -> None:
    """Launch the AegisScan production web server."""
    server_address = ("127.0.0.1", port)
    try:
        httpd = _ExclusiveHTTPServer(server_address, AegisScanRequestHandler)
    except OSError as exc:
        print(
            f"\nERROR: could not start on port {port}: {exc}\n"
            "  Another AegisScan (or other program) is probably already using it.\n"
            "  Stop that process, or choose another port with --port.",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"\n{'='*62}")
    print("  AEGISSCAN COMMAND CENTER")
    print(f"  -> http://localhost:{port}")
    print("  Press Ctrl+C to stop.")
    if _allow_any_path():
        print("\n  WARNING: AEGISSCAN_ALLOW_ANY_PATH is set - the server will scan ANY directory.")
    hint = _ui_build_hint()
    if hint:
        print(f"\n  NOTE: {hint}")
    print(f"{'='*62}\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping AegisScan server...")
        httpd.server_close()
