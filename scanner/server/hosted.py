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
            "history": not hosted,
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
    try:
        thread.start()
    except RuntimeError:
        # No worker ever ran, so nothing else will release the slot or clean up.
        if on_finish:
            on_finish()
        raise
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


def remove_tree(path: Path) -> None:
    """Delete a folder tree even when it holds read-only files (git marks its pack files read-only,
    and plain rmtree(ignore_errors=True) silently leaves them behind on Windows)."""
    import stat
    import sys

    def _make_writable_and_retry(func, target, *_exc_info) -> None:
        try:
            os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
            func(target)
        except OSError:
            pass  # best effort; the TTL sweep tries again later

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_make_writable_and_retry)
    else:
        shutil.rmtree(path, onerror=_make_writable_and_retry)


def delete_workspace(path: Path) -> None:
    remove_tree(path)


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
                remove_tree(child)
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


# ---------------------------------------------------------------- uploads
class UploadError(ValueError):
    """A rejected upload. `status` is the HTTP status to answer with."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


_COPY_CHUNK = 64 * 1024
_BOMB_RATIO = 100            # a single file expanding more than this ...
_BOMB_MIN_BYTES = 5 * MB     # ... and larger than this is treated as a decompression bomb


def clean_label(raw: str | None, default: str = "uploaded-folder") -> str:
    """A safe display name from a client-supplied name: no path parts, no odd characters."""
    name = re.split(r"[\\/]", str(raw or ""))[-1]
    name = re.sub(r"\.zip$", "", name, flags=re.IGNORECASE)
    name = re.sub(r"[^A-Za-z0-9._ -]", "", name).strip(" .-")
    return name[:60] or default


def _safe_member_path(name: str) -> str:
    """Normalise a zip member name and reject anything that could escape the destination."""
    cleaned = name.replace("\\", "/")
    if "\x00" in cleaned or cleaned.startswith("/") or re.match(r"^[A-Za-z]:", cleaned):
        raise UploadError("The zip contains an absolute path, which is not allowed.")
    parts = [p for p in cleaned.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise UploadError("The zip contains a path that leaves its folder, which is not allowed.")
    return "/".join(parts)


def extract_zip(data: bytes, dest: Path) -> tuple[int, int]:
    """Safely unpack an uploaded zip into dest. Returns (files, bytes written).

    Rejects path traversal and absolute paths, skips symlinks, refuses encrypted entries, caps the
    file count and the real number of bytes written (header sizes are not trusted), and refuses
    single entries with a decompression-bomb ratio.
    """
    import io
    import stat
    import zipfile

    file_limit = max_files()
    byte_limit = max_unpacked_bytes()
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise UploadError("That is not a valid zip file.") from exc

    dest_resolved = dest.resolve()
    files = 0
    written = 0
    with archive:
        infos = archive.infolist()
        if len(infos) > file_limit * 2:  # directories count too; fail fast on absurd archives
            raise UploadError(f"The zip has too many entries (limit {file_limit} files).", 413)
        for info in infos:
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                raise UploadError("The zip contains encrypted files, which cannot be scanned.")
            if stat.S_ISLNK(info.external_attr >> 16):
                continue  # never create symlinks from untrusted archives
            rel = _safe_member_path(info.filename)
            if not rel:
                continue
            files += 1
            if files > file_limit:
                raise UploadError(f"The zip has more than {file_limit} files. Remove generated or vendored folders.", 413)
            if info.compress_size and info.file_size > _BOMB_MIN_BYTES and info.file_size / info.compress_size > _BOMB_RATIO:
                raise UploadError("The zip looks like a decompression bomb and was rejected.")
            target = (dest / rel).resolve()
            if dest_resolved not in target.parents:
                raise UploadError("The zip contains a path that leaves its folder, which is not allowed.")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as src, open(target, "wb") as out:
                while True:
                    chunk = src.read(_COPY_CHUNK)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > byte_limit:
                        raise UploadError(
                            f"The unpacked folder is larger than {byte_limit // MB} MB.", 413
                        )
                    out.write(chunk)
    if files == 0:
        raise UploadError("The zip contains no files to scan.")
    return files, written


# ---------------------------------------------------------------- Git URLs
class GitError(ValueError):
    """A rejected or failed clone. Messages are safe to show to users (no server paths)."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


_MAX_URL_LENGTH = 300
_CLONE_TIMEOUT_S = 120


def _host_addresses(host: str) -> list[str]:
    import socket

    try:
        return sorted({str(info[4][0]) for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})
    except socket.gaierror as exc:
        raise GitError("That host name could not be found.") from exc


def validate_git_url(raw: str) -> str:
    """Accept only plain public https:// repository URLs.

    Blocks other schemes, embedded credentials, odd ports, and any host that resolves to a private,
    loopback, link-local or otherwise non-public address, so the server cannot be pointed at
    internal services (SSRF). Redirects are disabled at clone time as well.
    """
    import ipaddress
    from urllib.parse import urlparse

    url = (raw or "").strip()
    if not url or len(url) > _MAX_URL_LENGTH or re.search(r"[\s\x00-\x1f]", url):
        raise GitError("Enter a valid https Git URL, for example https://github.com/owner/repo.")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise GitError("Only https:// Git URLs are supported.")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or host == "localhost" or host.endswith((".local", ".internal")):
        raise GitError("That host is not allowed.")
    if parsed.username or parsed.password:
        raise GitError("Git URLs with a username or password are not supported.")
    if parsed.port not in (None, 443):
        raise GitError("Only the standard https port is supported.")
    if len([seg for seg in parsed.path.split("/") if seg]) < 1:
        raise GitError("The URL must point at a repository, for example https://github.com/owner/repo.")
    for address in _host_addresses(host):
        try:
            ip = ipaddress.ip_address(address.split("%")[0])
        except ValueError as exc:
            raise GitError("That host could not be verified.") from exc
        if not ip.is_global:
            raise GitError("That host points to a private address and is not allowed.")
    return url


def repo_label(url: str) -> str:
    """owner/repo from a Git URL, as a safe display name."""
    from urllib.parse import urlparse

    segments = [s for s in urlparse(url).path.split("/") if s]
    if segments and segments[-1].endswith(".git"):
        segments[-1] = segments[-1][:-4]
    return clean_label("/".join(segments[-2:]).replace("/", "-"), default="repository")


def _clone_env(home: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "SYSTEMROOT", "SystemRoot", "TEMP", "TMP", "TMPDIR")}
    env.update({
        "HOME": str(home),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "",
        "GCM_INTERACTIVE": "never",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    })
    return env


def clone_repo(url: str, dest: Path, timeout: float = _CLONE_TIMEOUT_S) -> None:
    """Shallow-clone a validated URL into the empty folder `dest`, then drop the .git folder.

    No hooks or templates, https only, no redirects, no prompts, no inherited git config or secrets
    from the environment, a hard time limit, and the same size and file-count caps as uploads.
    """
    import subprocess

    command = [
        "git",
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "-c", "http.followRedirects=false",
        "-c", "core.symlinks=false",
        "clone", "--quiet", "--depth", "1", "--single-branch", "--no-tags", "--template=", "--",
        url, str(dest),
    ]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argument list, URL validated above
            command, cwd=str(dest.parent), env=_clone_env(dest.parent), stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except FileNotFoundError as exc:
        raise GitError("Git is not available on this server.", 501) from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"Cloning took longer than {int(timeout)} seconds and was stopped.", 504) from exc
    if completed.returncode != 0:
        raise GitError("Could not clone that repository. Check the URL and that the repository is public.")

    remove_tree(dest / ".git")
    files = 0
    size = 0
    for entry in dest.rglob("*"):
        if entry.is_symlink():
            entry.unlink(missing_ok=True)  # never follow links out of the clone
        elif entry.is_file():
            files += 1
            size += entry.stat().st_size
            if files > max_files():
                raise GitError(f"The repository has more than {max_files()} files.", 413)
            if size > max_unpacked_bytes():
                raise GitError(f"The repository is larger than {max_unpacked_bytes() // MB} MB.", 413)
