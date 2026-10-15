from __future__ import annotations

import sqlite3
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


class PolicyCache:
    """Atomic local policy cache.  It never defaults to allow on a cache miss."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(self.path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS decisions (subject_id TEXT NOT NULL, source_id TEXT NOT NULL, resource_id TEXT NOT NULL, scope TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, version INTEGER NOT NULL, PRIMARY KEY(subject_id, source_id, resource_id, scope))")
        self.db.execute("CREATE TABLE IF NOT EXISTS request_contexts (decision_id TEXT PRIMARY KEY, application_id TEXT NOT NULL, subject_id TEXT NOT NULL, resources_json TEXT NOT NULL, expires_at TEXT NOT NULL)")
        self.db.commit()

    def install(self, version: int, decisions: list[dict[str, object]], *, full_snapshot: bool = False) -> bool:
        """Atomically install a newer policy; returns False for an idempotent retry.

        SQLite's transaction guarantees that a malformed payload leaves the
        prior committed policy intact.  A version rollback is rejected before
        any decision rows are touched.
        """
        current = self.version()
        if version < current:
            raise ValueError("STALE_POLICY")
        if version == current:
            return False
        with self.db:
            if full_snapshot:
                self.db.execute("DELETE FROM decisions")
            for row in decisions:
                self.db.execute("INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(subject_id, source_id, resource_id, scope) DO UPDATE SET decision=excluded.decision, reason=excluded.reason, version=excluded.version", (str(row["subject_id"]), str(row["source_id"]), str(row["resource_id"]), str(row.get("scope", "read")), str(row["decision"]), str(row.get("reason", "effective_access")), version))
            self.db.execute("INSERT INTO metadata VALUES ('version', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(version),))
        return True

    def version(self) -> int:
        row = self.db.execute("SELECT value FROM metadata WHERE key='version'").fetchone()
        return int(row[0]) if row else 0

    def decide(self, subject_id: str, source_id: str, resource_id: str, scope: str) -> tuple[str, str]:
        row = self.db.execute("SELECT decision, reason FROM decisions WHERE subject_id=? AND source_id=? AND resource_id=? AND scope=?", (subject_id, source_id, resource_id, scope)).fetchone()
        return (str(row[0]), str(row[1])) if row else ("unknown", "POLICY_MISSING")

    def save_context(self, decision_id: str, application_id: str, subject_id: str, resource_ids: list[str], *, ttl_seconds: int = 300) -> None:
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()
        with self.db:
            self.db.execute("DELETE FROM request_contexts WHERE expires_at < ?", (datetime.now(timezone.utc).isoformat(),))
            self.db.execute("INSERT INTO request_contexts VALUES (?, ?, ?, ?, ?)", (decision_id, application_id, subject_id, json.dumps(sorted(set(resource_ids))), expires_at))

    def load_context(self, decision_id: str, application_id: str, subject_id: str) -> set[str] | None:
        row = self.db.execute("SELECT resources_json, expires_at FROM request_contexts WHERE decision_id=? AND application_id=? AND subject_id=?", (decision_id, application_id, subject_id)).fetchone()
        if not row or str(row[1]) < datetime.now(timezone.utc).isoformat():
            return None
        return set(json.loads(str(row[0])))
