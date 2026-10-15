from __future__ import annotations

import sqlite3
import json
from threading import RLock
from datetime import datetime, timedelta, timezone
from pathlib import Path


class PolicyCache:
    """Atomic local policy cache.  It never defaults to allow on a cache miss."""

    def __init__(self, path: str, *, max_audit_records: int = 10_000) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # The FastAPI data plane and the background synchronizer run in
        # different threads.  Serialize access to one durable local database
        # connection so policy checks cannot race an installation transaction.
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self._lock = RLock()
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS decisions (subject_id TEXT NOT NULL, source_id TEXT NOT NULL, resource_id TEXT NOT NULL, scope TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, version INTEGER NOT NULL, PRIMARY KEY(subject_id, source_id, resource_id, scope))")
        self.db.execute("CREATE TABLE IF NOT EXISTS request_contexts (decision_id TEXT PRIMARY KEY, application_id TEXT NOT NULL, subject_id TEXT NOT NULL, resources_json TEXT NOT NULL, expires_at TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS audit_buffer (event_id TEXT PRIMARY KEY, application_id TEXT NOT NULL, subject_id TEXT NOT NULL, request_id TEXT NOT NULL, result TEXT NOT NULL, reason TEXT NOT NULL, policy_version INTEGER NOT NULL, created_at TEXT NOT NULL, delivered_at TEXT)")
        self.max_audit_records = max(1, max_audit_records)
        self.db.commit()

    def install(self, version: int, decisions: list[dict[str, object]], *, full_snapshot: bool = False) -> bool:
        """Atomically install a newer policy; returns False for an idempotent retry.

        SQLite's transaction guarantees that a malformed payload leaves the
        prior committed policy intact.  A version rollback is rejected before
        any decision rows are touched.
        """
        with self._lock:
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
        with self._lock:
            row = self.db.execute("SELECT value FROM metadata WHERE key='version'").fetchone()
        return int(row[0]) if row else 0

    def decide(self, subject_id: str, source_id: str, resource_id: str, scope: str) -> tuple[str, str]:
        with self._lock:
            row = self.db.execute("SELECT decision, reason FROM decisions WHERE subject_id=? AND source_id=? AND resource_id=? AND scope=?", (subject_id, source_id, resource_id, scope)).fetchone()
        return (str(row[0]), str(row[1])) if row else ("unknown", "POLICY_MISSING")

    def save_context(self, decision_id: str, application_id: str, subject_id: str, resource_ids: list[str], *, ttl_seconds: int = 300) -> None:
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()
        with self._lock:
            with self.db:
                self.db.execute("DELETE FROM request_contexts WHERE expires_at < ?", (datetime.now(timezone.utc).isoformat(),))
                self.db.execute("INSERT INTO request_contexts VALUES (?, ?, ?, ?, ?)", (decision_id, application_id, subject_id, json.dumps(sorted(set(resource_ids))), expires_at))

    def load_context(self, decision_id: str, application_id: str, subject_id: str) -> set[str] | None:
        with self._lock:
            row = self.db.execute("SELECT resources_json, expires_at FROM request_contexts WHERE decision_id=? AND application_id=? AND subject_id=?", (decision_id, application_id, subject_id)).fetchone()
        if not row or str(row[1]) < datetime.now(timezone.utc).isoformat():
            return None
        return set(json.loads(str(row[0])))

    def buffer_audit(
        self,
        event_id: str,
        *,
        application_id: str,
        subject_id: str,
        request_id: str,
        result: str,
        reason: str,
        policy_version: int,
    ) -> bool:
        """Persist only decision metadata. Raw prompts, documents, and output are never stored."""
        with self._lock:
            with self.db:
                inserted = self.db.execute(
                    "INSERT OR IGNORE INTO audit_buffer VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                    (event_id, application_id, subject_id, request_id, result, reason, policy_version, datetime.now(timezone.utc).isoformat()),
                ).rowcount > 0
                overflow = self.db.execute("SELECT COUNT(*) FROM audit_buffer").fetchone()[0] - self.max_audit_records
                if overflow > 0:
                    # Delivered entries are expendable first; if the control plane is down
                    # for too long, discard only the oldest metadata records to bound disk use.
                    self.db.execute(
                        "DELETE FROM audit_buffer WHERE event_id IN (SELECT event_id FROM audit_buffer ORDER BY delivered_at IS NULL, created_at ASC LIMIT ?)",
                        (overflow,),
                    )
        return inserted

    def pending_audit(self, limit: int = 100) -> list[dict[str, object]]:
        with self._lock:
            rows = self.db.execute(
                "SELECT event_id, application_id, subject_id, request_id, result, reason, policy_version FROM audit_buffer WHERE delivered_at IS NULL ORDER BY created_at ASC LIMIT ?",
                (max(1, min(limit, 100)),),
            ).fetchall()
        return [
            {"event_id": row[0], "application_id": row[1], "subject_id": row[2], "request_id": row[3], "result": row[4], "reason": row[5], "policy_version": row[6]}
            for row in rows
        ]

    def mark_audit_delivered(self, event_ids: list[str]) -> None:
        if not event_ids:
            return
        with self._lock:
            with self.db:
                self.db.executemany(
                    "UPDATE audit_buffer SET delivered_at=? WHERE event_id=? AND delivered_at IS NULL",
                    [(datetime.now(timezone.utc).isoformat(), event_id) for event_id in event_ids],
                )
