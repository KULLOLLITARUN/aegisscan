"""Pure-Python secret scanner fallback: non-Python languages and common credential idioms.

Found by the multi-language benchmark: the fallback only opened .py/.js/.ts/config/markdown files,
so hardcoded secrets in Java, Go, PHP and C# were never even read.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from scanner.static_analysis.gitleaks_runner import _run_python_secret_scanner


def _scan(tmp_path: Path, name: str, content: str):
    (tmp_path / name).write_text(content, encoding="utf-8")
    return _run_python_secret_scanner(tmp_path)


@pytest.mark.parametrize(
    "name,line,issue",
    [
        ("A.java", 'private static final String DB_PASSWORD = "Pr0d-Passw0rd-2024!";', "Hardcoded Password String"),
        ("main.go", 'const apiSecret = "sk_live_51HxK9aB3cD4eF5gH6iJ7kL8mN9oP0qR"', "Stripe Live API Key"),
        ("index.php", '$db = new mysqli("localhost", "root", "Sup3rS3cret-Prod!", "shop");',
         "Hardcoded Database Password (positional argument)"),
        ("index.php", '$c = mysqli_connect("localhost", "root", "Sup3rS3cret-Prod!");',
         "Hardcoded Database Password (positional argument)"),
        ("db.php", '$pdo = new PDO("mysql:host=db;dbname=app", "app", "Sup3rS3cret-Prod!");',
         "Hardcoded Database Password (positional argument)"),
        ("Svc.cs", 'const string Cs = "Server=db;Database=app;User Id=sa;Password=Adm1n-Pr0d-2024;";',
         "Hardcoded Password in Connection String"),
        ("app.properties", 'jdbc.url=jdbc:sqlserver://db;user=sa;password=Adm1n-Pr0d-2024;', "Hardcoded Password in Connection String"),
    ],
)
def test_hardcoded_credentials_are_found_in_non_python_files(tmp_path: Path, name: str, line: str, issue: str) -> None:
    findings = _scan(tmp_path, name, f"// header\n{line}\n")
    assert [(f.line_start, f.issue_type) for f in findings] == [(2, issue)]
    assert findings[0].file_path.name == name


@pytest.mark.parametrize(
    "name,line",
    [
        ("Svc.cs", 'const string Cs = "Server=db;Password={0};";'),                       # format placeholder
        ("Svc.cs", 'const string Cs = "Server=db;Password=%s;";'),
        ("Svc.cs", 'const string Cs = "Server=db;Pwd=$DB_PASS;";'),
        ("Svc.cs", 'const string Cs = "Server=db;Password=short;";'),                     # under 6 chars
        ("safe.php", '$db = new mysqli("localhost", getenv("DB_USER"), getenv("DB_PASS"), "shop");'),
        ("safe.php", '$pdo = new PDO($dsn, $user, $pass);'),
        ("safe.php", '$db = new mysqli("localhost", "root", "", "shop");'),               # empty password
        ("A.java", 'private final String dbPassword = System.getenv("DB_PASSWORD");'),
    ],
)
def test_placeholders_and_env_lookups_are_not_flagged(tmp_path: Path, name: str, line: str) -> None:
    assert _scan(tmp_path, name, line + "\n") == []


def test_unrelated_extensions_are_still_skipped(tmp_path: Path) -> None:
    findings = _scan(tmp_path, "notes.txt", 'password = "Pr0d-Passw0rd-2024!"\n')
    assert findings == []


def test_excluded_directories_are_still_skipped(tmp_path: Path) -> None:
    vendored = tmp_path / "node_modules" / "pkg"
    vendored.mkdir(parents=True)
    (vendored / "index.js").write_text('const password = "Pr0d-Passw0rd-2024!";\n')
    assert _run_python_secret_scanner(tmp_path) == []
