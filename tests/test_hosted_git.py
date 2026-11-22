"""Git-URL scanning in hosted mode: URL validation (SSRF guards), safe clone flags, and the scan flow."""
from __future__ import annotations

import json
import socket
import subprocess
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scanner.models.finding import Finding, Severity
from scanner.models.scan import ScanResult
from scanner.server import hosted
from scanner.server.app import AegisScanRequestHandler

TOKEN = "g" * 24
PUBLIC_IP = "140.82.112.3"


class _Dummy:
    pass


def _fake_dns(mapping: dict[str, list[str]]):
    def getaddrinfo(host, port, *args, **kwargs):
        if host not in mapping:
            raise socket.gaierror("not found")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in mapping[host]]

    return getaddrinfo


@pytest.fixture(autouse=True)
def hosted_env(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGISSCAN_MODE", "hosted")
    monkeypatch.setenv("AEGISSCAN_ACCESS_TOKEN", TOKEN)
    monkeypatch.setenv("AEGISSCAN_WORKSPACE_DIR", str(tmp_path / "ws"))
    for var in ("AEGISSCAN_ALLOWED_HOSTS", "RENDER_EXTERNAL_HOSTNAME", "AEGISSCAN_MAX_FILES", "AEGISSCAN_MAX_UNPACKED_MB"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(hosted, "_scan_limiter", hosted.RateLimiter(100, 60))
    monkeypatch.setattr(hosted, "_slots", hosted.ScanSlots(2))
    monkeypatch.setattr(socket, "getaddrinfo", _fake_dns({
        "github.com": [PUBLIC_IP],
        "internal.example": ["10.0.0.5"],
        "loop.example": ["127.0.0.1"],
        "meta.example": ["169.254.169.254"],
        "mixed.example": [PUBLIC_IP, "192.168.1.9"],
        "v6.example": ["::1"],
    }))


# ------------------------------------------------------------------ URL validation
@pytest.mark.parametrize("url", ["https://github.com/owner/repo", "https://github.com/owner/repo.git", "  https://github.com/owner/repo  "])
def test_public_https_urls_are_accepted(url: str) -> None:
    assert hosted.validate_git_url(url) == url.strip()


@pytest.mark.parametrize("url", [
    "", "   ", "github.com/owner/repo",
    "http://github.com/owner/repo",
    "git://github.com/owner/repo",
    "ssh://git@github.com/owner/repo",
    "file:///etc/passwd",
    "ftp://github.com/owner/repo",
    "https://user:pass@github.com/owner/repo",
    "https://token@github.com/owner/repo",
    "https://github.com:8443/owner/repo",
    "https://github.com",
    "https://github.com/owner/repo with space",
    "https://github.com/owner/repo\nhttps://evil.example",
    "https://localhost/owner/repo",
    "https://printer.local/owner/repo",
    "https://db.internal/owner/repo",
    "https://nosuchhost.example/owner/repo",
    "https://github.com/" + "a" * 400,
])
def test_unsafe_or_malformed_urls_are_rejected(url: str) -> None:
    with pytest.raises(hosted.GitError):
        hosted.validate_git_url(url)


@pytest.mark.parametrize("host", ["internal.example", "loop.example", "meta.example", "mixed.example", "v6.example"])
def test_hosts_resolving_to_non_public_addresses_are_rejected(host: str) -> None:
    with pytest.raises(hosted.GitError) as exc:
        hosted.validate_git_url(f"https://{host}/owner/repo")
    assert "private" in str(exc.value)


def test_ip_literal_hosts_are_checked_too(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", socket.getaddrinfo.__class__ and (lambda host, port, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, port))]))
    for literal in ("127.0.0.1", "10.1.2.3", "169.254.169.254"):
        with pytest.raises(hosted.GitError):
            hosted.validate_git_url(f"https://{literal}/owner/repo")


@pytest.mark.parametrize("url,label", [
    ("https://github.com/owner/repo", "owner-repo"),
    ("https://github.com/owner/repo.git", "owner-repo"),
    ("https://gitlab.com/group/sub/repo", "sub-repo"),
    ("https://github.com/o/../../etc", "etc"),
])
def test_repo_label(url: str, label: str) -> None:
    assert hosted.repo_label(url) == label


# ------------------------------------------------------------------ clone
def _fake_git(monkeypatch, *, returncode: int = 0, files: dict[str, str] | None = None, error: Exception | None = None):
    calls: dict = {}

    def run(command, **kwargs):
        calls["command"], calls["kwargs"] = command, kwargs
        if error:
            raise error
        dest = Path(command[-1])
        for name, text in (files or {"a.py": "x = 1\n"}).items():
            f = dest / name
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text, encoding="utf-8")
        (dest / ".git").mkdir(exist_ok=True)
        (dest / ".git" / "config").write_text("[core]\n", encoding="utf-8")
        return subprocess.CompletedProcess(command, returncode, "", "fatal: details with a path")

    monkeypatch.setattr(subprocess, "run", run)
    return calls


def test_clone_uses_the_safe_flags_and_a_scrubbed_environment(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("GROQ_API_KEY", "secret-should-not-leak")
    monkeypatch.setenv("AEGISSCAN_ACCESS_TOKEN", TOKEN)
    calls = _fake_git(monkeypatch)
    dest = tmp_path / "code"
    dest.mkdir()
    hosted.clone_repo("https://github.com/owner/repo", dest)

    cmd = calls["command"]
    assert cmd[0] == "git"
    for needle in ("protocol.allow=never", "protocol.https.allow=always", "http.followRedirects=false", "--depth", "--no-tags", "--template="):
        assert needle in cmd
    assert cmd[-3:-1] == ["--", "https://github.com/owner/repo"]
    env = calls["kwargs"]["env"]
    assert env["GIT_TERMINAL_PROMPT"] == "0" and env["GIT_CONFIG_NOSYSTEM"] == "1"
    leaked = [v for v in env.values() if "secret-should-not-leak" in v or TOKEN in v]
    assert leaked == []  # the server's own secrets are never handed to git
    assert calls["kwargs"]["timeout"] == 120 and calls["kwargs"]["stdin"] == subprocess.DEVNULL


def test_clone_removes_the_git_folder(tmp_path, monkeypatch) -> None:
    _fake_git(monkeypatch)
    dest = tmp_path / "code"
    dest.mkdir()
    hosted.clone_repo("https://github.com/owner/repo", dest)
    assert sorted(p.name for p in dest.rglob("*")) == ["a.py"]


def test_clone_failure_message_does_not_echo_git_output(tmp_path, monkeypatch) -> None:
    _fake_git(monkeypatch, returncode=128)
    dest = tmp_path / "code"
    dest.mkdir()
    with pytest.raises(hosted.GitError) as exc:
        hosted.clone_repo("https://github.com/owner/repo", dest)
    assert "public" in str(exc.value) and "fatal" not in str(exc.value) and str(tmp_path) not in str(exc.value)


def test_clone_timeout_and_missing_git(tmp_path, monkeypatch) -> None:
    dest = tmp_path / "code"
    dest.mkdir()
    _fake_git(monkeypatch, error=subprocess.TimeoutExpired("git", 120))
    with pytest.raises(hosted.GitError) as exc:
        hosted.clone_repo("https://github.com/owner/repo", dest)
    assert exc.value.status == 504
    _fake_git(monkeypatch, error=FileNotFoundError())
    with pytest.raises(hosted.GitError) as exc:
        hosted.clone_repo("https://github.com/owner/repo", dest)
    assert exc.value.status == 501


def test_clone_enforces_file_and_size_caps(tmp_path, monkeypatch) -> None:
    dest = tmp_path / "code"
    dest.mkdir()
    monkeypatch.setenv("AEGISSCAN_MAX_FILES", "2")
    _fake_git(monkeypatch, files={f"f{i}.py": "x\n" for i in range(4)})
    with pytest.raises(hosted.GitError) as exc:
        hosted.clone_repo("https://github.com/owner/repo", dest)
    assert exc.value.status == 413

    monkeypatch.delenv("AEGISSCAN_MAX_FILES")
    monkeypatch.setenv("AEGISSCAN_MAX_UNPACKED_MB", "1")
    dest2 = tmp_path / "code2"
    dest2.mkdir()
    _fake_git(monkeypatch, files={"big.bin": "x" * (2 * 1024 * 1024)})
    with pytest.raises(hosted.GitError) as exc:
        hosted.clone_repo("https://github.com/owner/repo", dest2)
    assert exc.value.status == 413


def test_clone_deletes_symlinks(tmp_path, monkeypatch) -> None:
    dest = tmp_path / "code"
    dest.mkdir()
    calls = _fake_git(monkeypatch)
    real_run = subprocess.run

    def run_with_link(command, **kwargs):
        done = real_run(command, **kwargs)
        try:
            (Path(command[-1]) / "link").symlink_to(tmp_path)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not permitted on this system")
        return done

    monkeypatch.setattr(subprocess, "run", run_with_link)
    hosted.clone_repo("https://github.com/owner/repo", dest)
    assert not (dest / "link").exists() and not (dest / "link").is_symlink()
    assert calls["command"]


# ------------------------------------------------------------------ scan flow
def _post(body: dict):
    raw = json.dumps(body).encode()
    h = AegisScanRequestHandler.__new__(AegisScanRequestHandler)
    h.command, h.path = "POST", "/api/scan"
    h.requestline = "POST /api/scan HTTP/1.1"
    h.client_address = ("203.0.113.9", 4000)
    h.server = _Dummy()
    h.headers = {"Authorization": f"Bearer {TOKEN}", "Content-Length": str(len(raw))}
    h.rfile = BytesIO(raw)
    h.wfile = BytesIO()
    h.send_response = MagicMock()
    h.send_header = MagicMock()
    h.end_headers = MagicMock()
    h.send_error = MagicMock()
    h.do_POST()
    return h


def _status(h) -> int:
    return h.send_response.call_args[0][0]


def _out(h) -> dict:
    return json.loads(h.wfile.getvalue().decode())


def _leftover_workspaces() -> list[Path]:
    root = hosted.workspace_root()
    return list(root.iterdir()) if root.exists() else []


def test_git_scan_clones_scans_labels_and_always_cleans_up(monkeypatch) -> None:
    calls = _fake_git(monkeypatch)
    seen: dict = {}

    def fake_run(**kwargs):
        seen["files"] = sorted(p.name for p in kwargs["path"].rglob("*") if p.is_file())
        finding = Finding(
            file_path=kwargs["path"] / "a.py", issue_type="t", category="other", severity=Severity.LOW,
            confidence=0.7, line_start=1, line_end=1, evidence="e", explanation="x", rule_source="bandit",
        )
        return ScanResult(target_path=kwargs["path"], findings=[finding], files_analyzed=1), None, None

    monkeypatch.setattr("main.run", fake_run)
    h = _post({"git_url": "https://github.com/owner/repo"})
    assert _status(h) == 200
    out = _out(h)
    assert out["target_path"] == "owner-repo" and out["findings"][0]["file_path"] == "a.py"
    assert seen["files"] == ["a.py"]  # scanned the clone, without .git
    assert calls["command"][0] == "git"
    assert _leftover_workspaces() == []  # the clone is deleted once the scan ends


def test_bad_git_url_is_400_and_creates_no_workspace() -> None:
    for url in ("http://github.com/o/r", "https://internal.example/o/r", "https://user:pw@github.com/o/r"):
        h = _post({"git_url": url})
        assert _status(h) == 400
    assert _leftover_workspaces() == []


def test_clone_failure_is_reported_and_cleaned_up(monkeypatch) -> None:
    _fake_git(monkeypatch, returncode=128)
    h = _post({"git_url": "https://github.com/owner/repo"})
    assert _status(h) == 400 and "Could not clone" in _out(h)["error"]
    assert _leftover_workspaces() == []


def test_git_scan_when_busy_releases_nothing_and_leaves_no_clone(monkeypatch) -> None:
    slots = hosted.ScanSlots(1)
    monkeypatch.setattr(hosted, "_slots", slots)
    assert slots.try_acquire()
    h = _post({"git_url": "https://github.com/owner/repo"})
    assert _status(h) == 503
    assert _leftover_workspaces() == []
    slots.release()


def test_upload_id_wins_when_both_sources_are_given(monkeypatch) -> None:
    wid, ws = hosted.new_workspace()
    (hosted.code_dir(ws) / "a.py").write_text("x = 1\n", encoding="utf-8")
    calls = _fake_git(monkeypatch)
    monkeypatch.setattr("main.run", lambda **kw: (ScanResult(target_path=kw["path"], files_analyzed=1), None, None))
    h = _post({"upload_id": wid, "git_url": "https://github.com/owner/repo"})
    assert _status(h) == 200
    assert "command" not in calls  # git was never invoked
