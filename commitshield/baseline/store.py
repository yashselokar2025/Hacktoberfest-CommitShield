"""
Baseline Store — SQLite-based finding persistence for change-aware classification.

This module maintains a local database of security findings across commits,
enabling CommitShield to classify findings as:
  NEW / EXISTING / RESOLVED / CHANGED / UNCERTAIN

This is what enables the key innovation: distinguishing newly introduced
security risks from pre-existing security debt.

Unlike detect-secrets (which uses a JSON file with no history), CommitShield's
SQLite store tracks finding state across multiple commits with timestamps,
severity transitions, and resolution events.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from commitshield.core.finding import (
    ChangeStatus,
    Confidence,
    DependencyFinding,
    SecretFinding,
    Severity,
)

DEFAULT_DB_PATH = Path.home() / ".commitshield" / "findings.db"
SCHEMA_VERSION = 1


class BaselineStore:
    """
    SQLite-backed store for persistent finding history.

    Enables change-aware classification by maintaining a record of
    previously seen findings, their statuses, and resolution events.
    """

    def __init__(self, db_path: Path = DEFAULT_DB_PATH) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._path = db_path
        self._conn: sqlite3.Connection | None = None
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self._path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def _ensure_schema(self) -> None:
        conn = self._connect()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            );

            CREATE TABLE IF NOT EXISTS secret_findings (
                finding_id      TEXT PRIMARY KEY,
                rule_id         TEXT NOT NULL,
                rule_name       TEXT NOT NULL,
                severity        TEXT NOT NULL,
                confidence      TEXT NOT NULL,
                file_path       TEXT NOT NULL,
                matched_value   TEXT NOT NULL,   -- ALWAYS REDACTED
                repo_path       TEXT NOT NULL,
                first_seen      TEXT NOT NULL,
                last_seen       TEXT NOT NULL,
                status          TEXT NOT NULL DEFAULT 'active',  -- active / resolved
                commit_sha      TEXT,
                scan_count      INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS dependency_findings (
                finding_id      TEXT PRIMARY KEY,
                package_name    TEXT NOT NULL,
                version         TEXT NOT NULL,
                ecosystem       TEXT NOT NULL,
                priority        TEXT NOT NULL,
                advisory_sev    TEXT NOT NULL,
                cve_ids         TEXT NOT NULL,   -- JSON array
                repo_path       TEXT NOT NULL,
                first_seen      TEXT NOT NULL,
                last_seen       TEXT NOT NULL,
                status          TEXT NOT NULL DEFAULT 'active',
                scan_count      INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS scan_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_path       TEXT NOT NULL,
                scanned_at      TEXT NOT NULL,
                files_scanned   INTEGER,
                secrets_found   INTEGER,
                deps_checked    INTEGER,
                new_findings    INTEGER,
                resolved_findings INTEGER,
                base_commit     TEXT,
                scan_mode       TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_secrets_repo
                ON secret_findings(repo_path);
            CREATE INDEX IF NOT EXISTS idx_deps_repo
                ON dependency_findings(repo_path);
        """)
        conn.commit()

    # ─────────────────────────────────────────────────────────────
    # Secret findings
    # ─────────────────────────────────────────────────────────────

    def load_secret_baseline(self, repo_path: str) -> dict[str, dict]:
        """
        Load all active secret findings for this repository.
        Returns a dict keyed by finding_id.
        """
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM secret_findings WHERE repo_path = ? AND status = 'active'",
            (repo_path,),
        ).fetchall()
        return {row["finding_id"]: dict(row) for row in rows}

    def classify_secret_findings(
        self,
        current_findings: list[SecretFinding],
        repo_path: str,
    ) -> list[SecretFinding]:
        """
        Classify findings against the baseline:
          NEW       — not in baseline
          EXISTING  — already known, not resolved
          RESOLVED  — in baseline but not in current scan
          CHANGED   — same location, different confidence/severity

        Also marks findings in baseline that are no longer present as RESOLVED.
        Returns the current_findings list with change_status populated.
        """
        baseline = self.load_secret_baseline(repo_path)
        current_ids = {f.finding_id for f in current_findings}
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()

        # Classify each current finding
        classified = []
        for finding in current_findings:
            if finding.finding_id in baseline:
                baseline_entry = baseline[finding.finding_id]
                # Check if severity/confidence changed significantly
                if (baseline_entry["severity"] != finding.severity.value or
                        baseline_entry["confidence"] != finding.confidence.value):
                    finding.change_status = ChangeStatus.CHANGED
                    finding.is_newly_introduced = False
                else:
                    finding.change_status = ChangeStatus.EXISTING
                    finding.is_newly_introduced = False
                # Update last_seen and scan_count
                conn.execute(
                    "UPDATE secret_findings SET last_seen=?, scan_count=scan_count+1 "
                    "WHERE finding_id=?",
                    (now, finding.finding_id),
                )
            else:
                finding.change_status = ChangeStatus.NEW
                finding.is_newly_introduced = True
            classified.append(finding)

        # Mark baseline entries not in current scan as RESOLVED
        resolved_ids = set(baseline.keys()) - current_ids
        for fid in resolved_ids:
            conn.execute(
                "UPDATE secret_findings SET status='resolved', last_seen=? WHERE finding_id=?",
                (now, fid),
            )

        conn.commit()
        return classified

    def save_secret_findings(
        self,
        findings: list[SecretFinding],
        repo_path: str,
        commit_sha: str = "",
    ) -> None:
        """Persist new secret findings to the baseline store."""
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        for f in findings:
            if f.change_status != ChangeStatus.NEW:
                continue
            conn.execute(
                """
                INSERT OR IGNORE INTO secret_findings
                    (finding_id, rule_id, rule_name, severity, confidence, file_path,
                     matched_value, repo_path, first_seen, last_seen, commit_sha)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f.finding_id, f.rule_id, f.rule_name,
                    f.severity.value, f.confidence.value, f.file_path,
                    f.matched_value, repo_path, now, now, commit_sha,
                ),
            )
        conn.commit()

    # ─────────────────────────────────────────────────────────────
    # Dependency findings
    # ─────────────────────────────────────────────────────────────

    def load_dep_baseline(self, repo_path: str) -> dict[str, dict]:
        """Load all active dependency findings for this repo."""
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM dependency_findings WHERE repo_path = ? AND status = 'active'",
            (repo_path,),
        ).fetchall()
        return {row["finding_id"]: dict(row) for row in rows}

    def classify_dep_findings(
        self,
        current_deps: list[DependencyFinding],
        repo_path: str,
    ) -> list[DependencyFinding]:
        """Classify dependency findings as newly introduced or existing."""
        baseline = self.load_dep_baseline(repo_path)
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()

        for dep in current_deps:
            if dep.finding_id in baseline:
                dep.is_newly_introduced = False
                conn.execute(
                    "UPDATE dependency_findings SET last_seen=?, scan_count=scan_count+1 "
                    "WHERE finding_id=?",
                    (now, dep.finding_id),
                )
            else:
                dep.is_newly_introduced = True

        conn.commit()
        return current_deps

    def save_dep_findings(
        self,
        findings: list[DependencyFinding],
        repo_path: str,
    ) -> None:
        """Persist new dependency findings to the baseline store."""
        import json
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        for f in findings:
            if not f.is_newly_introduced:
                continue
            conn.execute(
                """
                INSERT OR IGNORE INTO dependency_findings
                    (finding_id, package_name, version, ecosystem, priority,
                     advisory_sev, cve_ids, repo_path, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f.finding_id, f.package_name, f.version, f.ecosystem,
                    f.priority, f.advisory_severity,
                    json.dumps(f.cve_ids), repo_path, now, now,
                ),
            )
        conn.commit()

    # ─────────────────────────────────────────────────────────────
    # Scan history
    # ─────────────────────────────────────────────────────────────

    def record_scan(
        self,
        repo_path: str,
        files_scanned: int,
        secrets_found: int,
        deps_checked: int,
        new_findings: int,
        resolved_findings: int,
        base_commit: str = "",
        scan_mode: str = "staged",
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        conn.execute(
            """
            INSERT INTO scan_history
                (repo_path, scanned_at, files_scanned, secrets_found, deps_checked,
                 new_findings, resolved_findings, base_commit, scan_mode)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (repo_path, now, files_scanned, secrets_found, deps_checked,
             new_findings, resolved_findings, base_commit, scan_mode),
        )
        conn.commit()

    def get_scan_history(self, repo_path: str, limit: int = 20) -> list[dict]:
        """Return recent scan history for a repository."""
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM scan_history WHERE repo_path=? ORDER BY scanned_at DESC LIMIT ?",
            (repo_path, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def clear_repo_baseline(self, repo_path: str) -> None:
        """Clear all findings for a repository (use with care)."""
        conn = self._connect()
        conn.execute("DELETE FROM secret_findings WHERE repo_path=?", (repo_path,))
        conn.execute("DELETE FROM dependency_findings WHERE repo_path=?", (repo_path,))
        conn.execute("DELETE FROM scan_history WHERE repo_path=?", (repo_path,))
        conn.commit()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    # ─────────────────────────────────────────────────────────────
    # v2 adapter methods — used by the post-processor CLI scan flow
    # ─────────────────────────────────────────────────────────────

    def load_known_ids(self, repo_path: str) -> set[str]:
        """
        Return the set of finding_ids already in the baseline for this repo.
        Used by the v2 scan flow to classify findings as NEW vs EXISTING.
        """
        conn = self._connect()
        rows = conn.execute(
            "SELECT finding_id FROM secret_findings WHERE repo_path=? AND status='active'",
            (repo_path,),
        ).fetchall()
        return {row["finding_id"] for row in rows}

    def save_new(self, findings: list, repo_path: str) -> None:
        """
        Persist NEW CandidateFinding objects (with _classification attached)
        to the baseline store.

        Uses a simple finding_id derived from rule_id + file_path + matched_value
        to deduplicate across commits.
        """
        import hashlib
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()

        for f in findings:
            # Build a stable ID from the finding's key fields
            key = f"{f.rule_id}:{f.file_path}:{f.matched_value}"
            finding_id = hashlib.sha256(key.encode()).hexdigest()[:16]

            cls = getattr(f, "_classification", None)
            confidence = cls.confidence_label if cls else "UNKNOWN"
            severity   = cls.urgency if cls else "UNKNOWN"
            commit_sha = getattr(f, "commit", "")

            conn.execute(
                """
                INSERT OR IGNORE INTO secret_findings
                    (finding_id, rule_id, rule_name, severity, confidence, file_path,
                     matched_value, repo_path, first_seen, last_seen, commit_sha)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    f.rule_id,
                    getattr(f, "rule_description", f.rule_id),
                    severity,
                    confidence,
                    f.file_path,
                    f.matched_value,
                    repo_path,
                    now, now,
                    commit_sha,
                ),
            )
        conn.commit()

