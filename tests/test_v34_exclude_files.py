"""`.aegisscan.toml` exclude_files: matching files are skipped by every stage."""
from __future__ import annotations

from pathlib import Path

from scanner.config import ScanConfig, load_config
from scanner.static_analysis.gitleaks_runner import run_gitleaks  # noqa: F401
from scanner.static_analysis.runner import run_all_tools


def test_pattern_matching() -> None:
    c = ScanConfig(exclude_files=(".env", "*.pem", "config/local.*"))
    assert c.is_file_excluded(".env")
    assert c.is_file_excluded("a/b/.env")
    assert c.is_file_excluded("keys/Server.PEM")
    assert c.is_file_excluded("config/local.py")
    assert not c.is_file_excluded("src/config/local.py")
    assert not c.is_file_excluded("env.py")
    assert not ScanConfig().is_file_excluded(".env")


def test_load_config_reads_and_validates(tmp_path: Path) -> None:
    (tmp_path / ".aegisscan.toml").write_text('exclude_files = [".env"]\n', encoding="utf-8")
    assert load_config(tmp_path).exclude_files == (".env",)
    (tmp_path / ".aegisscan.toml").write_text("exclude_files = 5\n", encoding="utf-8")
    assert load_config(tmp_path).exclude_files == ()


def test_excluded_file_gets_no_findings(tmp_path: Path) -> None:
    secret = 'password = "hunter2hunter2hunter2"\nimport os\nos.system(input())\n'
    (tmp_path / "keep.py").write_text(secret, encoding="utf-8")
    (tmp_path / "skip.py").write_text(secret, encoding="utf-8")
    before, _ = run_all_tools(tmp_path)
    assert {f.file_path.name for f in before} >= {"keep.py", "skip.py"}
    (tmp_path / ".aegisscan.toml").write_text('exclude_files = ["skip.py"]\n', encoding="utf-8")
    after, _ = run_all_tools(tmp_path)
    names = {f.file_path.name for f in after}
    assert "keep.py" in names and "skip.py" not in names
