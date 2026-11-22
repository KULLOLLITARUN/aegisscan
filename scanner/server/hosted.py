"""
Hosted-mode support for the AegisScan web server.

Local mode (the default) scans a typed path on the machine running the server. Hosted mode
(AEGISSCAN_MODE=hosted, e.g. on Render) never reads server paths: users supply code by upload
or Git URL, every API call needs an access token, results are scrubbed of server paths, and
there is no shared history or user-supplied API key.

Everything here reads its settings from the environment on each call, so it can be tested and
reconfigured without restarting.
"""
from __future__ import annotations

import hmac
import os
import re
import shutil
import tempfile
import threading
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Callable

# ---------------------------------------------------------------- settings
MB = 1024 * 1024
DEFAULT_MAX_UPLOAD_MB = 50
DEFAULT_MAX_UNPACKED_MB = 200
DEFAULT_MAX_FILES = 5000
DEFAULT_SCAN_TIMEOUT_S = 300
DEFAULT_MAX_CONCURRENT = 2
DEFAULT_WORKSPACE_TTL_S = 30 * 60
DEFAULT_RATE_LIMIT = 10          # scans or uploads ...
DEFAULT_RATE_WINDOW_S = 10 * 60  # ... per client per window


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default
    return value if value > 0 else default


def is_hosted() -> bool:
    return os.environ.get("AEGISSCAN_MODE", "").strip().lower() == "hosted"


def access_token() -> str:
    return os.environ.get("AEGISSCAN_ACCESS_TOKEN", "")


def llm_enabled() -> bool:
    """Hosted scans are static-only unless the operator opts in (and supplies GROQ_API_KEY)."""
    return os.environ.get("AEGISSCAN_HOSTED_LLM", "").strip().lower() in ("1", "true", "yes")


def max_upload_bytes() -> int:
    return _env_int("AEGISSCAN_MAX_UPLOAD_MB", DEFAULT_MAX_UPLOAD_MB) * MB


def max_unpacked_bytes() -> int:
    return _env_int("AEGISSCAN_MAX_UNPACKED_MB", DEFAULT_MAX_UNPACKED_MB) * MB


def max_files() -> int:
    return _env_int("AEGISSCAN_MAX_FILES", DEFAULT_MAX_FILES)


def scan_timeout_seconds() -> int:
    return _env_int("AEGISSCAN_SCAN_TIMEOUT_S", DEFAULT_SCAN_TIMEOUT_S)


def startup_errors() -> list[str]:
    """Reasons hosted mode must not start (an open scanner on the internet is never intended)."""
    errors: list[str] = []
    if is_hosted() and len(access_token()) < 16:
        errors.append(
            "AEGISSCAN_MODE=hosted needs AEGISSCAN_ACCESS_TOKEN set to at least 16 characters."
        )
    return errors


def public_config() -> dict[str, Any]:
    """What the UI may know before it has a token."""
    hosted = is_hosted()
    return {
        "mode": "hosted" if hosted else "local",
        "auth_required": hosted,
        "features": {
            "path": not hosted,
            "upload": hosted,
            "git": hosted,
            "llm": (not hosted) or llm_enabled(),
        },
        "limits": {
            "max_upload_mb": max_upload_bytes() // MB,
            "max_files": max_files(),
            "scan_timeout_s": scan_timeout_seconds(),
        } if hosted else {},
    }


# ---------------------------------------------------------------- auth and hosts
def authorized(headers: Any) -> bool:
    """True when hosted auth is satisfied (always True in local mode)."""
    if not is_hosted():
        return True
    expected = access_token()
    if not expected:
        return False
    header = headers.get("Authorization") or ""
    scheme, _, supplied = header.partition(" ")
    if scheme.lower() != "bearer":
        return False
    return hmac.compare_digest(supplied.strip().encode("utf-8"), expected.encode("utf-8"))


def allowed_hosts() -> set[str]:
    """Host names the hosted server answers to (lowercase, no port). Empty = no Host filtering
    (the access token still protects every API call)."""
    hosts = {h.strip().lower() for h in os.environ.get("AEGISSCAN_ALLOWED_HOSTS", "").split(",") if h.strip()}
    render = os.environ.get("RENDER_EXTERNAL_HOSTNAME", "").strip().lower()
    if render:
        hosts.add(render)
    return hosts


def client_ip(headers: Any, client_address: Any) -> str:
    """Best client address. Behind Render's proxy the rightmost X-Forwarded-For entry is the one
    the proxy itself observed; earlier entries are client-supplied and spoofable."""
    if is_hosted():
        forwarded = (headers.get("X-Forwarded-For") or "").split(",")
        last = forwarded[-1].strip()
        if last:
            return last
    try:
        return str(client_address[0])
    except (TypeError, IndexError):
        return "unknown"


# ---------------------------------------------------------------- limits
class RateLimiter:
    """Sliding-window limiter: at most `limit` events per `window` seconds per key."""

    def __init__(self, limit: int, window: float, clock: Callable[[], float] = time.monotonic) -> None:
        self.limit = limit
        self.window = window
        self._clock = clock
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            q = self._events[key]
            while q and now - q[0] >= self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True


class ScanSlots:
    """Caps concurrent scans. try_acquire never blocks: a busy server says so immediately."""

    def __init__(self, size: int) -> None:
        self._sem = threading.BoundedSemaphore(size)

    def try_acquire(self) -> bool:
        return self._sem.acquire(blocking=False)

    def release(self) -> None:
        self._sem.release()


_slots = ScanSlots(_env_int("AEGISSCAN_MAX_CONCURRENT", DEFAULT_MAX_CONCURRENT))
_scan_limiter = RateLimiter(_env_int("AEGISSCAN_RATE_LIMIT", DEFAULT_RATE_LIMIT), DEFAULT_RATE_WINDOW_S)
_upload_limiter = RateLimiter(_env_int("AEGISSCAN_RATE_LIMIT", DEFAULT_RATE_LIMIT), DEFAULT_RATE_WINDOW_S)


def slots() -> ScanSlots:
    return _slots


def scan_limiter() -> RateLimiter:
    return _scan_limiter


def upload_limiter() -> RateLimiter:
    return _upload_limiter


class ScanTimeout(Exception):
    """The scan exceeded the hosted time limit."""


def run_with_timeout(fn: Callable[[], Any], timeout: float, on_finish: Callable[[], None] | None = None) -> Any:
    """Run fn in a worker thread and wait up to `timeout` seconds.

    A Python thread cannot be killed, so on timeout the caller gets ScanTimeout immediately while
    the worker keeps running; `on_finish` (slot release, temp-folder cleanup) runs only when the
    worker really ends, so a runaway scan can never be stacked on top of new ones.
    """
    box: dict[str, Any] = {}

    def _worker() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised in the caller
            box["error"] = exc
        finally:
            if on_finish:
                try:
                    on_finish()
                except Exception:  # noqa: BLE001
                    pass

    thread = threading.Thread(target=_worker, name="aegisscan-hosted-scan", daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise ScanTimeout(f"The scan took longer than {int(timeout)} seconds and was stopped.")
    if "error" in box:
        raise box["error"]
    return box["value"]


# ---------------------------------------------------------------- temp workspaces
_WORKSPACE_ID = re.compile(r"^[0-9a-f]{32}$")


def workspace_root() -> Path:
    return Path(os.environ.get("AEGISSCAN_WORKSPACE_DIR") or Path(tempfile.gettempdir()) / "aegisscan-workspaces")


def new_workspace() -> tuple[str, Path]:
    """A private, empty workspace for one upload or clone. The id is unguessable.
    Layout: <root>/<id>/code (what gets scanned) and <root>/<id>/label.txt (display name)."""
    sweep()
    root = workspace_root()
    root.mkdir(parents=True, exist_ok=True)
    wid = uuid.uuid4().hex
    path = root / wid
    (path / "code").mkdir(parents=True)
    return wid, path


def code_dir(workspace: Path) -> Path:
    return workspace / "code"


def write_label(workspace: Path, label: str) -> None:
    (workspace / "label.txt").write_text(label[:120], encoding="utf-8")


def read_label(workspace: Path, default: str = "uploaded code") -> str:
    try:
        return (workspace / "label.txt").read_text(encoding="utf-8").strip() or default
    except OSError:
        return default


def get_workspace(workspace_id: str) -> Path | None:
    if not isinstance(workspace_id, str) or not _WORKSPACE_ID.match(workspace_id):
        return None
    path = workspace_root() / workspace_id
    return path if (path / "code").is_dir() else None


def delete_workspace(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)


def sweep(ttl_seconds: int = DEFAULT_WORKSPACE_TTL_S) -> int:
    """Delete workspaces older than the TTL. Called on every new workspace."""
    root = workspace_root()
    if not root.is_dir():
        return 0
    removed = 0
    cutoff = time.time() - ttl_seconds
    for child in root.iterdir():
        try:
            if child.is_dir() and child.stat().st_mtime < cutoff:
                shutil.rmtree(child, ignore_errors=True)
                removed += 1
        except OSError:
            continue
    return removed


# ---------------------------------------------------------------- scrubbing server paths
def sanitize_text(text: str, root: Path, label: str) -> str:
    """Replace the server-side workspace path in a message with a neutral label."""
    out = str(text)
    for variant in {str(root), root.as_posix(), str(root.resolve()), root.resolve().as_posix()}:
        out = out.replace(variant, label)
    return out


def sanitize_result(result: Any, root: Path, label: str) -> None:
    """Make a ScanResult safe to return to a hosted user: target and finding paths become relative
    to the uploaded code, so no server temp path ever reaches the browser."""
    resolved = root.resolve()
    for finding in result.findings:
        raw = Path(finding.file_path)
        for base in (root, resolved):
            try:
                finding.file_path = Path(raw.relative_to(base).as_posix())
                break
            except ValueError:
                continue
    result.target_path = Path(label)
