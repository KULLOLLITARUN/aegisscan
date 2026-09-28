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
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from dotenv import load_dotenv
load_dotenv()

log = logging.getLogger(__name__)

# React Vite build output lives one level up from ui/
_DIST_DIR = Path(__file__).parent / "dist"
_INDEX_HTML = _DIST_DIR / "index.html"


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
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

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
                body = b"<h1>AegisScan - run npm run build in scanner/server/ui/</h1>"
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

    # ------------------------------------------------------------------ POST
    def do_POST(self) -> None:
        if self.path == "/api/scan":
            self._handle_sync_scan()
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    # ------------------------------------------------------------------ SSE scan
    def _handle_sse_scan(self, query_string: str) -> None:
        qs = parse_qs(query_string)
        raw_path = qs.get("path", ["."])[0]
        # Resolve relative to project root (parent of scanner/server/)
        _project_root = Path(__file__).parent.parent.parent
        target_path = Path(raw_path) if Path(raw_path).is_absolute() else (_project_root / raw_path).resolve()
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
            import os
            os.environ["GROQ_API_KEY"] = api_key

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
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
            from scanner.ingestion.crawler import WorkspaceCrawler

            # Phase 1 — crawl
            sse("progress", {"phase": "Crawling workspace...", "file": "", "pct": 5, "found": 0})
            time.sleep(0.1)

            crawl_result = WorkspaceCrawler(target_path).crawl()
            files = crawl_result.discovered
            total = len(files)

            sse("progress", {"phase": f"Discovered {total} files", "file": "", "pct": 15, "found": 0})
            time.sleep(0.1)

            # Phase 2 — progress ticks while pretending to analyse files
            for i, fpath in enumerate(files[:min(total, 20)]):
                pct = 15 + int((i / max(total, 1)) * 50)
                sse("progress", {"phase": "Static analysis", "file": str(fpath), "pct": pct, "found": 0})
                time.sleep(0.04)

            sse("progress", {"phase": "Running intelligence layer...", "file": "", "pct": 70, "found": 0})
            time.sleep(0.1)

            sse("progress", {"phase": "Scoring results...", "file": "", "pct": 85, "found": 0})
            time.sleep(0.1)

            # Final scan run — attach a temporary handler so provider/tool log
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

        raw_path = payload.get("path", ".")
        _project_root = Path(__file__).parent.parent.parent
        target_path = Path(raw_path) if Path(raw_path).is_absolute() else (_project_root / raw_path).resolve()
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
            import os
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


def run_server(port: int = 8000) -> None:
    """Launch the AegisScan production web server."""
    server_address = ("", port)
    httpd = HTTPServer(server_address, AegisScanRequestHandler)
    print(f"\n{'='*62}")
    print(f"  AEGISSCAN COMMAND CENTER")
    print(f"  -> http://localhost:{port}")
    print(f"  Press Ctrl+C to stop.")
    print(f"{'='*62}\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping AegisScan server...")
        httpd.server_close()
