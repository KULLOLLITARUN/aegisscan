"""
ScanHistoryDB — V9 SQLite scan history persistence engine.

Manages recording and querying historical scan results and security score trends.
"""
from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scanner.models.scan import ScanResult

log = logging.getLogger(__name__)

_DEFAULT_DB_NAME = ".aegisscan_history.db"
_SCHEMA_FILE = Path(__file__).parent / "schema.sql"


class ScanHistoryDB:
    """SQLite engine for storing and analyzing AegisScan history."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or Path(_DEFAULT_DB_NAME)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initialize database schema from schema.sql if not exists."""
        schema_sql = _SCHEMA_FILE.read_text(encoding="utf-8")
        with self._get_connection() as conn:
            conn.executescript(schema_sql)

    def record_scan(self, result: ScanResult) -> str:
        """Record a completed ScanResult into the SQLite database."""
        from scanner.models.finding import Severity

        findings_by_sev = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0,
        }
        for f in result.findings:
            if f.severity in findings_by_sev:
                findings_by_sev[f.severity] += 1

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO scans (
                    scan_id, target_path, security_score, optimization_score,
                    files_analyzed, files_discovered, total_findings,
                    critical_count, high_count, medium_count, low_count, info_count,
                    llm_requests_count, llm_latency_seconds, duration_seconds
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.scan_id,
                    str(result.target_path.resolve()),
                    result.security_score,
                    result.optimization_score,
                    result.files_analyzed,
                    result.files_discovered,
                    len(result.findings),
                    findings_by_sev[Severity.CRITICAL],
                    findings_by_sev[Severity.HIGH],
                    findings_by_sev[Severity.MEDIUM],
                    findings_by_sev[Severity.LOW],
                    findings_by_sev[Severity.INFO],
                    result.llm_requests_count,
                    result.llm_total_latency_seconds,
                    result.scan_duration_seconds,
                ),
            )

            conn.executemany(
                """
                INSERT INTO scan_findings (
                    finding_id, scan_id, file_path, issue_type, category,
                    severity, confidence, line_start, line_end, rule_source, has_fix_patch
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        f.id,
                        result.scan_id,
                        str(f.file_path),
                        f.issue_type,
                        f.category,
                        f.severity.value,
                        f.confidence,
                        f.line_start,
                        f.line_end,
                        f.rule_source,
                        bool(f.fix_patch),
                    )
                    for f in result.findings
                ],
            )
        log.info("Recorded scan %s to history DB at %s", result.scan_id, self.db_path)
        return result.scan_id

    def get_history(self, target_path: Path | None = None, limit: int = 20) -> list[dict[str, Any]]:
        """Retrieve recent scan history rows."""
        query = "SELECT * FROM scans"
        params: list[Any] = []
        if target_path:
            query += " WHERE target_path = ?"
            params.append(str(target_path.resolve()))
        query += " ORDER BY timestamp DESC, rowid DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def get_latest_score_delta(self, target_path: Path | None = None) -> dict[str, float] | None:
        """Calculate security/optimization score delta between latest scan and previous scan."""
        history = self.get_history(target_path=target_path, limit=2)
        if len(history) < 2:
            return None

        latest = history[0]
        prev = history[1]

        latest_sec = latest["security_score"] or 100.0
        prev_sec = prev["security_score"] or 100.0
        latest_opt = latest["optimization_score"] or 100.0
        prev_opt = prev["optimization_score"] or 100.0

        return {
            "security_delta": round(latest_sec - prev_sec, 1),
            "optimization_delta": round(latest_opt - prev_opt, 1),
        }
