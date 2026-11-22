"""Folder upload (POST /api/upload) and safe zip extraction in hosted mode."""
from __future__ import annotations

import io
import json
import stat
import zipfile
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scanner.models.finding import Finding, Severity
from scanner.models.scan import ScanResult
from scanner.server import hosted
from scanner.server.app import AegisScanRequestHandler

TOKEN = "u" * 24


class _Dummy:
    pass


def _zip_bytes(entries: dict[str, str | bytes], *, symlinks: dict[str, str] | None = None, encrypted: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, content)
        for name, target in (symlinks or {}).items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, target)
    data = bytearray(buf.getvalue())
    if encrypted:
        # writestr() resets flag_bits, so set the "encrypted" bit directly in every header.
        for sig, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            pos = data.find(sig)
            while pos != -1:
                data[pos + offset] |= 0x1
                pos = data.find(sig, pos + 4)
    return bytes(data)


def _post(path: str, data: bytes | None, headers: dict | None = None, *, length: int | None = None):
    h = AegisScanRequestHandler.__new__(AegisScanRequestHandler)
    h.command, h.path = "POST", path
    h.requestline = f"POST {path} HTTP/1.1"
    h.client_address = ("203.0.113.9", 4000)
    h.server = _Dummy()
    body = data or b""
    hdrs = {"Authorization": f"Bearer {TOKEN}", **(headers or {})}
    hdrs["Content-Length"] = str(len(body) if length is None else length)
    h.headers = hdrs
    h.rfile = BytesIO(body)
    h.wfile = BytesIO()
    h.send_response = MagicMock()
    h.send_header = MagicMock()
    h.end_headers = MagicMock()
    h.send_error = MagicMock()
    h.do_POST()
    return h


def _body(h) -> dict:
    return json.loads(h.wfile.getvalue().decode())


def _status(h) -> int:
    return h.send_response.call_args[0][0]


@pytest.fixture(autouse=True)
def hosted_env(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGISSCAN_MODE", "hosted")
    monkeypatch.setenv("AEGISSCAN_ACCESS_TOKEN", TOKEN)
    monkeypatch.setenv("AEGISSCAN_WORKSPACE_DIR", str(tmp_path / "ws"))
    for var in ("AEGISSCAN_ALLOWED_HOSTS", "RENDER_EXTERNAL_HOSTNAME", "AEGISSCAN_MAX_FILES", "AEGISSCAN_MAX_UNPACKED_MB", "AEGISSCAN_MAX_UPLOAD_MB"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(hosted, "_upload_limiter", hosted.RateLimiter(100, 60))
    monkeypatch.setattr(hosted, "_scan_limiter", hosted.RateLimiter(100, 60))
    monkeypatch.setattr(hosted, "_slots", hosted.ScanSlots(2))


def _workspaces() -> list[Path]:
    root = hosted.workspace_root()
    return [p for p in root.iterdir()] if root.exists() else []


# ------------------------------------------------------------------ happy path
def test_valid_upload_is_unpacked_and_described() -> None:
    data = _zip_bytes({"a.py": "x = 1\n", "pkg/b.py": "y = 2\n"})
    h = _post("/api/upload", data, {"X-Upload-Name": "My App.zip"})
    assert _status(h) == 200
    out = _body(h)
    assert out["files"] == 2 and out["label"] == "My App" and out["bytes"] == len("x = 1\n") + len("y = 2\n")
    ws = hosted.get_workspace(out["upload_id"])
    assert ws is not None
    assert (hosted.code_dir(ws) / "pkg" / "b.py").read_text() == "y = 2\n"
    assert str(ws) not in json.dumps(out)  # the response never reveals server paths


def test_upload_then_scan_uses_the_unpacked_code(monkeypatch) -> None:
    out = _body(_post("/api/upload", _zip_bytes({"a.py": "x = 1\n"}), {"X-Upload-Name": "demo.zip"}))
    seen: dict = {}

    def fake_run(**kwargs):
        seen["files"] = sorted(p.name for p in kwargs["path"].rglob("*") if p.is_file())
        finding = Finding(
            file_path=kwargs["path"] / "a.py", issue_type="t", category="other", severity=Severity.LOW,
            confidence=0.7, line_start=1, line_end=1, evidence="e", explanation="x", rule_source="bandit",
        )
        return ScanResult(target_path=kwargs["path"], findings=[finding], files_analyzed=1), None, None

    monkeypatch.setattr("main.run", fake_run)
    h = _post("/api/scan", json.dumps({"upload_id": out["upload_id"]}).encode())
    assert _status(h) == 200
    assert seen["files"] == ["a.py"]
    result = _body(h)
    assert result["target_path"] == "demo" and result["findings"][0]["file_path"] == "a.py"


@pytest.mark.parametrize("raw,expected", [
    ("../../My App!.zip", "My App"),
    ("C:\\Users\\me\\proj.zip", "proj"),
    ("", "uploaded-folder"),
    ("..", "uploaded-folder"),
    ("a" * 200, "a" * 60),
])
def test_label_is_cleaned(raw: str, expected: str) -> None:
    assert hosted.clean_label(raw) == expected


# ------------------------------------------------------------------ hostile archives
@pytest.mark.parametrize("name", ["../evil.txt", "a/../../evil.txt", "/etc/passwd", "C:/Windows/evil.txt", "..\\evil.txt"])
def test_path_traversal_and_absolute_paths_are_rejected_and_cleaned_up(name: str, tmp_path) -> None:
    h = _post("/api/upload", _zip_bytes({"ok.py": "x\n", name: "pwned"}))
    assert _status(h) == 400
    assert _workspaces() == []  # the half-created workspace is deleted
    assert not (tmp_path / "evil.txt").exists() and not (tmp_path / "ws" / "evil.txt").exists()


def test_symlinks_are_skipped_not_created() -> None:
    data = _zip_bytes({"a.py": "x\n"}, symlinks={"link": "/etc/passwd"})
    h = _post("/api/upload", data)
    assert _status(h) == 200
    ws = hosted.get_workspace(_body(h)["upload_id"])
    assert sorted(p.name for p in hosted.code_dir(ws).rglob("*")) == ["a.py"]


def test_encrypted_entries_are_rejected() -> None:
    h = _post("/api/upload", _zip_bytes({"a.py": "x\n"}, encrypted=True))
    assert _status(h) == 400 and "encrypted" in _body(h)["error"]
    assert _workspaces() == []


def test_not_a_zip_is_rejected() -> None:
    h = _post("/api/upload", b"this is plain text, not a zip file")
    assert _status(h) == 400 and "valid zip" in _body(h)["error"]
    assert _workspaces() == []


def test_empty_zip_is_rejected() -> None:
    h = _post("/api/upload", _zip_bytes({"emptydir/": ""}))
    assert _status(h) == 400
    assert _workspaces() == []


def test_too_many_files_is_rejected(monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_MAX_FILES", "3")
    h = _post("/api/upload", _zip_bytes({f"f{i}.py": "x\n" for i in range(5)}))
    assert _status(h) == 413
    assert _workspaces() == []


def test_unpacked_size_is_capped_by_bytes_actually_written(monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_MAX_UNPACKED_MB", "1")
    noisy = bytes(range(256)) * 8192  # 2 MB that does not compress to nothing
    h = _post("/api/upload", _zip_bytes({"big.bin": noisy}))
    assert _status(h) == 413 and "larger than 1 MB" in _body(h)["error"]
    assert _workspaces() == []


def test_decompression_bomb_is_rejected() -> None:
    h = _post("/api/upload", _zip_bytes({"bomb.txt": b"\x00" * (8 * 1024 * 1024)}))
    assert _status(h) == 400 and "bomb" in _body(h)["error"]
    assert _workspaces() == []


# ------------------------------------------------------------------ request-level rules
def test_oversized_content_length_is_refused_before_reading(monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_MAX_UPLOAD_MB", "1")
    h = _post("/api/upload", b"x", length=5 * 1024 * 1024)
    assert _status(h) == 413 and h.rfile.tell() == 0  # body was never read
    assert _workspaces() == []


def test_missing_content_length_is_411() -> None:
    h = _post("/api/upload", b"", length=0)
    assert _status(h) == 411


def test_truncated_body_is_rejected() -> None:
    h = _post("/api/upload", b"short", length=500)
    assert _status(h) == 400
    assert _workspaces() == []


def test_upload_needs_the_token() -> None:
    h = _post("/api/upload", _zip_bytes({"a.py": "x\n"}), {"Authorization": "Bearer wrong"})
    assert _status(h) == 401
    assert _workspaces() == []


def test_upload_is_rate_limited(monkeypatch) -> None:
    monkeypatch.setattr(hosted, "_upload_limiter", hosted.RateLimiter(1, 60))
    data = _zip_bytes({"a.py": "x\n"})
    assert _status(_post("/api/upload", data)) == 200
    assert _status(_post("/api/upload", data)) == 429


def test_upload_is_unavailable_in_local_mode(monkeypatch) -> None:
    monkeypatch.setenv("AEGISSCAN_MODE", "local")
    h = _post("/api/upload", _zip_bytes({"a.py": "x\n"}))
    assert _status(h) == 404


def test_extract_zip_blocks_member_escaping_through_a_symlinked_parent(tmp_path) -> None:
    """Even if a path resolves outside dest after normalisation, it is refused."""
    dest = tmp_path / "dest"
    dest.mkdir()
    with pytest.raises(hosted.UploadError):
        hosted.extract_zip(_zip_bytes({"ok.py": "x\n", "sub/../../escape.py": "no"}), dest)
    assert not (tmp_path / "escape.py").exists()
