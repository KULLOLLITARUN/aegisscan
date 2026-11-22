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
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any
from urllib.parse import parse_qs, urlparse

from dotenv import load_dotenv

from . import hosted

load_dotenv()

log = logging.getLogger(__name__)

# React Vite build output; the source lives in <repo root>/ui and builds into this package
_DIST_DIR = Path(__file__).parent / "dist"
_INDEX_HTML = _DIST_DIR / "index.html"

_PROJECT_ROOT = Path(__file__).parent.parent.parent
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "[::1]"}
_MAX_JSON_BODY = 1024 * 1024  # scan requests are small JSON documents


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


def _as_bool(value: Any, default: bool) -> bool:
    """Booleans arrive as real bools (JSON body) or strings (query string)."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return _parse_qs_bool(str(value), default)


def _normalize_scan_params(params: dict) -> dict:
    """One shape for scan options, whether they came from a query string or a JSON body."""
    return {
        "path": str(params.get("path") or "."),
        "upload_id": str(params.get("upload_id") or ""),
        "git_url": str(params.get("git_url") or "").strip(),
        "static_only": _as_bool(params.get("static_only"), True),
        "deep": _as_bool(params.get("deep"), False),
        "generate_patches": _as_bool(params.get("generate_patches"), False),
        "privacy": str(params.get("privacy") or "standard"),
        "api_key": str(params.get("api_key") or "").strip(),
    }


def _apply_privacy(p: dict) -> None:
    """privacy=strict means local static analysis only: no remote LLM calls of any kind."""
    if p["privacy"] == "strict":
        p["static_only"] = True
        p["deep"] = False
        p["generate_patches"] = False


class _SSELogHandler(logging.Handler):
    """Forwards Python log records (provider failover, rate limits, tool errors —
    everything that previously only reached the server's own terminal) to the
    browser as SSE "log" events, in real time, while a scan is in flight.

    thread_id: when set, only records emitted by that thread are forwarded (hosted mode, so users
    running scans at the same time never see each other's logs). scrub: message filter (hosted
    mode removes server paths)."""

    def __init__(self, sse_fn, thread_id: int | None = None, scrub=None) -> None:
        super().__init__()
        self._sse = sse_fn
        self._thread_id = thread_id
        self._scrub = scrub
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        if self._thread_id is not None and record.thread != self._thread_id:
            return
        try:
            message = self.format(record)
            if self._scrub:
                message = self._scrub(message)
            self._sse("log", {
                "ts": time.strftime("%H:%M:%S"),
                "level": record.levelname.lower(),
                "logger": record.name,
                "message": message,
            })
        except Exception:
            pass  # never let a logging hiccup break the scan itself


class AegisScanRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the AegisScan web server."""

    def setup(self) -> None:
        # Hosted mode: a client that stalls mid-request must not hold a server thread forever.
        super().setup()
        if hosted.is_hosted():
            self.connection.settimeout(120)

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
        if hosted.is_hosted():
            return self._hosted_request_allowed(host.lower())
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

    def _hosted_request_allowed(self, host: str) -> bool:
        """Hosted mode: the Host must be one of the configured public names (when any are set) and a
        browser Origin must be this same site. The access token is checked separately."""
        allowed = hosted.allowed_hosts()
        if allowed and host not in allowed:
            self._send_json({"error": "Forbidden host"}, status=HTTPStatus.FORBIDDEN)
            return False
        origin = self.headers.get("Origin")
        if origin:
            origin_host = (urlparse(origin).hostname or "").lower()
            if origin_host != host and origin_host not in allowed:
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

    # ------------------------------------------------------------------ gates
    def _require_auth(self) -> bool:
        if hosted.authorized(self.headers):
            return True
        self._send_json({"error": "A valid access token is required."}, status=HTTPStatus.UNAUTHORIZED)
        return False

    def _api_gate(self) -> bool:
        """Host/Origin checks, then (hosted mode only) the access token."""
        return self._request_allowed() and self._require_auth()

    def _read_json_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            length = 0
        raw = self.rfile.read(min(length, _MAX_JSON_BODY)) if length > 0 else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            return {}
        return data if isinstance(data, dict) else {}

    # ------------------------------------------------------------------ GET
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        # Health check (Render) and UI capabilities need no token.
        if path == "/api/health":
            self._send_json({"ok": True})
            return
        if path == "/api/config":
            if self._request_allowed():
                self._send_json(hosted.public_config())
            return

        if path.startswith("/api/") and not self._api_gate():
            return

        # ── Scan history ──────────────────────────────────────────────────
        if path == "/api/history":
            if hosted.is_hosted():
                self._send_json([])  # no history is kept or shared in hosted mode
                return
            qs = parse_qs(parsed.query)
            limit = int(qs.get("limit", ["20"])[0])
            from scanner.storage.history import ScanHistoryDB
            db = ScanHistoryDB()
            self._send_json(db.get_history(limit=limit))
            return

        # ── SSE live scan stream ─────────────────────────────────────────
        if path == "/api/scan/stream":
            self._handle_scan({k: v[0] for k, v in parse_qs(parsed.query).items()}, stream=True)
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
        path = urlparse(self.path).path
        if path in ("/api/scan", "/api/scan/stream"):
            if not self._api_gate():
                return
            self._handle_scan(self._read_json_body(), stream=path.endswith("/stream"))
        elif path == "/api/upload":
            if not self._api_gate():
                return
            self._handle_upload()
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    # ------------------------------------------------------------------ upload (hosted mode)
    def _handle_upload(self) -> None:
        """Receive a zip of the user's folder, unpack it safely into a private workspace and return
        an upload_id that /api/scan can use. The workspace is deleted after a time limit."""
        if not hosted.is_hosted():
            self._send_json({"error": "Uploads are only available in hosted mode."}, status=HTTPStatus.NOT_FOUND)
            return
        if not hosted.upload_limiter().allow(hosted.client_ip(self.headers, self.client_address)):
            self._send_json(
                {"error": "Too many uploads from your address. Wait a few minutes and try again."},
                status=HTTPStatus.TOO_MANY_REQUESTS,
            )
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            length = 0
        if length <= 0:
            self._send_json({"error": "The upload is empty."}, status=HTTPStatus.LENGTH_REQUIRED)
            return
        limit = hosted.max_upload_bytes()
        if length > limit:
            self._send_json(
                {"error": f"The upload is larger than {limit // hosted.MB} MB. Leave out large or generated folders and try again."},
                status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            )
            return

        data = self.rfile.read(length)
        if len(data) != length:
            self._send_json({"error": "The upload was cut short. Try again."}, status=HTTPStatus.BAD_REQUEST)
            return

        upload_id, workspace = hosted.new_workspace()
        try:
            files, size = hosted.extract_zip(data, hosted.code_dir(workspace))
        except hosted.UploadError as exc:
            hosted.delete_workspace(workspace)
            self._send_json({"error": str(exc)}, status=exc.status)
            return
        except Exception as exc:
            hosted.delete_workspace(workspace)
            log.error("Upload extraction failed: %s", exc, exc_info=True)
            self._send_json({"error": "The zip could not be unpacked."}, status=HTTPStatus.BAD_REQUEST)
            return

        label = hosted.clean_label(self.headers.get("X-Upload-Name"))
        hosted.write_label(workspace, label)
        self._send_json({"upload_id": upload_id, "label": label, "files": files, "bytes": size})

    # ------------------------------------------------------------------ scan entry point
    def _handle_scan(self, params: dict, stream: bool) -> None:
        p = _normalize_scan_params(params)
        if hosted.is_hosted():
            self._handle_hosted_scan(p, stream)
        else:
            self._handle_local_scan(p, stream)

    def _open_sse(self):
        """Send SSE headers and return a thread-safe sse(event, data) writer."""
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        lock = threading.Lock()

        def sse(event: str, data: Any) -> None:
            payload = f"event: {event}\ndata: {json.dumps(data)}\n\n"
            with lock:
                try:
                    self.wfile.write(payload.encode("utf-8"))
                    self.wfile.flush()
                except Exception:
                    pass

        return sse

    # ------------------------------------------------------------------ local scans
    def _handle_local_scan(self, p: dict, stream: bool) -> None:
        try:
            target_path = _resolve_scan_path(p["path"])
        except PermissionError as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.FORBIDDEN)
            return
        _apply_privacy(p)
        if p["api_key"]:
            os.environ["GROQ_API_KEY"] = p["api_key"]
        if stream:
            self._local_stream(target_path, p)
        else:
            self._local_sync(target_path, p)

    def _local_stream(self, target_path: Path, p: dict) -> None:
        sse = self._open_sse()
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
                    static_only=p["static_only"],
                    deep=p["deep"],
                    generate_patches=p["generate_patches"],
                    privacy=p["privacy"],
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

    def _local_sync(self, target_path: Path, p: dict) -> None:
        if not target_path.exists() or not target_path.is_dir():
            self._send_json({"error": f"Invalid path: {target_path}"}, status=HTTPStatus.BAD_REQUEST)
            return
        try:
            from main import run
            result, _, _ = run(
                path=target_path,
                static_only=p["static_only"],
                deep=p["deep"],
                generate_patches=p["generate_patches"],
                privacy=p["privacy"],
            )
            self._send_json(json.loads(result.model_dump_json()))
        except Exception as exc:
            import traceback
            log.error("Sync scan error: %s\n%s", exc, traceback.format_exc())
            self._send_json({"error": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    # ------------------------------------------------------------------ hosted scans
    def _hosted_source(self, p: dict):
        """Resolve the code to scan from an upload id or Git URL.
        Returns (target, label, cleanup, prepare) or None after sending an error response.
        `prepare` (Git only) clones into target inside the time-limited scan worker."""
        if p["upload_id"]:
            workspace = hosted.get_workspace(p["upload_id"])
            if workspace is None:
                self._send_json(
                    {"error": "That upload was not found or has expired. Choose the folder again."},
                    status=HTTPStatus.NOT_FOUND,
                )
                return None
            return hosted.code_dir(workspace), hosted.read_label(workspace), None, None
        if p["git_url"]:
            try:
                url = hosted.validate_git_url(p["git_url"])
            except hosted.GitError as exc:
                self._send_json({"error": str(exc)}, status=exc.status)
                return None
            _, workspace = hosted.new_workspace()
            target = hosted.code_dir(workspace)
            return (
                target,
                hosted.repo_label(url),
                lambda: hosted.delete_workspace(workspace),
                lambda: hosted.clone_repo(url, target),
            )
        self._send_json(
            {"error": "Provide an uploaded folder or a Git URL to scan."},
            status=HTTPStatus.BAD_REQUEST,
        )
        return None

    def _handle_hosted_scan(self, p: dict, stream: bool) -> None:
        ip = hosted.client_ip(self.headers, self.client_address)
        if not hosted.scan_limiter().allow(ip):
            self._send_json(
                {"error": "Too many scans from your address. Wait a few minutes and try again."},
                status=HTTPStatus.TOO_MANY_REQUESTS,
            )
            return

        # Hosted scans never use a user-supplied key, and stay static-only unless the operator opts in.
        p["api_key"] = ""
        if not hosted.llm_enabled():
            p.update(static_only=True, deep=False, generate_patches=False, privacy="strict")
        else:
            _apply_privacy(p)

        source = self._hosted_source(p)
        if source is None:
            return
        target, label, cleanup, prepare = source

        if not hosted.slots().try_acquire():
            if cleanup:
                cleanup()
            self._send_json(
                {"error": "The server is busy with other scans. Try again in a minute."},
                status=HTTPStatus.SERVICE_UNAVAILABLE,
            )
            return

        def on_finish() -> None:  # runs when the scan worker really ends (even after a timeout)
            hosted.slots().release()
            if cleanup:
                cleanup()

        if stream:
            self._hosted_stream(target, label, p, on_finish, prepare)
        else:
            self._hosted_sync(target, label, p, on_finish, prepare)

    def _hosted_run(self, target: Path, label: str, p: dict, on_finish, sse=None, prepare=None):
        """Run one hosted scan in a worker thread with a time limit; returns the sanitised ScanResult."""
        from main import run

        def scrub(text: str) -> str:
            return hosted.sanitize_text(text, target, label)

        def on_progress(phase: str, pct: int, detail: str = "") -> None:
            if sse:
                sse("progress", {
                    "phase": scrub(f"{phase}: {detail}" if detail else phase),
                    "file": "",
                    "pct": pct,
                    "found": 0,
                })

        def work():
            handler = None
            root_logger = logging.getLogger()
            prev_level = root_logger.level
            if sse:
                # Only this scan's own thread is forwarded, so concurrent users never see each other's logs.
                handler = _SSELogHandler(sse, thread_id=threading.get_ident(), scrub=scrub)
                handler.setLevel(logging.INFO)
                root_logger.addHandler(handler)
                root_logger.setLevel(min(prev_level or logging.WARNING, logging.INFO))
            try:
                if prepare:
                    on_progress("Cloning repository", 3)
                    prepare()
                result, _, _ = run(
                    path=target,
                    static_only=p["static_only"],
                    deep=p["deep"],
                    generate_patches=p["generate_patches"],
                    privacy=p["privacy"],
                    progress=on_progress if sse else None,
                    record_history=False,
                )
                return result
            finally:
                if handler:
                    root_logger.removeHandler(handler)
                    root_logger.setLevel(prev_level)

        result = hosted.run_with_timeout(work, hosted.scan_timeout_seconds(), on_finish)
        hosted.sanitize_result(result, target, label)
        return result

    def _hosted_stream(self, target: Path, label: str, p: dict, on_finish, prepare=None) -> None:
        sse = self._open_sse()
        try:
            result = self._hosted_run(target, label, p, on_finish, sse=sse, prepare=prepare)
            sse("progress", {"phase": "Complete", "file": "", "pct": 100, "found": len(result.findings)})
            sse("complete", json.loads(result.model_dump_json()))
        except hosted.ScanTimeout as exc:
            sse("error", {"error": str(exc)})
        except Exception as exc:
            log.error("Hosted scan error: %s", exc, exc_info=True)
            sse("error", {"error": hosted.sanitize_text(str(exc), target, label)})

    def _hosted_sync(self, target: Path, label: str, p: dict, on_finish, prepare=None) -> None:
        try:
            result = self._hosted_run(target, label, p, on_finish, prepare=prepare)
            self._send_json(json.loads(result.model_dump_json()))
        except hosted.ScanTimeout as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.GATEWAY_TIMEOUT)
        except hosted.GitError as exc:
            self._send_json({"error": str(exc)}, status=exc.status)
        except Exception as exc:
            log.error("Hosted scan error: %s", exc, exc_info=True)
            self._send_json(
                {"error": hosted.sanitize_text(str(exc), target, label)},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
            )


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


class _ExclusiveThreadingHTTPServer(ThreadingMixIn, _ExclusiveHTTPServer):
    """Hosted mode: one thread per request, so a long scan or SSE stream never blocks other users."""

    daemon_threads = True


def run_server(port: int = 8000) -> None:
    """Launch the AegisScan production web server."""
    problems = hosted.startup_errors()
    if problems:
        print("\nERROR: " + "\n       ".join(problems), file=sys.stderr)
        sys.exit(1)

    is_hosted = hosted.is_hosted()
    if is_hosted:
        # Render (and most hosts) tell the app which port to use via $PORT and need all interfaces.
        port = int(os.environ.get("PORT") or port)
        # All interfaces by default (required on Render); AEGISSCAN_HOST narrows it, e.g. for local testing.
        bind_host = os.environ.get("AEGISSCAN_HOST") or "0.0.0.0"  # noqa: S104 - token-protected
        server_address = (bind_host, port)
        server_class = _ExclusiveThreadingHTTPServer
    else:
        server_address = ("127.0.0.1", port)
        server_class = _ExclusiveHTTPServer
    try:
        httpd = server_class(server_address, AegisScanRequestHandler)
    except OSError as exc:
        print(
            f"\nERROR: could not start on port {port}: {exc}\n"
            "  Another AegisScan (or other program) is probably already using it.\n"
            "  Stop that process, or choose another port with --port.",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"\n{'='*62}")
    print("  AEGISSCAN COMMAND CENTER" + ("  (hosted mode)" if is_hosted else ""))
    print(f"  -> http://localhost:{port}")
    print("  Press Ctrl+C to stop.")
    if is_hosted:
        print("\n  Hosted mode: uploads and Git URLs only, access token required, no server paths.")
    elif _allow_any_path():
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
