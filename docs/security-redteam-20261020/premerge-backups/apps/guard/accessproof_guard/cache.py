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
        self.db.execute("CREATE TABLE IF NOT EXISTS bound_applications (application_id TEXT PRIMARY KEY, source_id TEXT NOT NULL, mode TEXT NOT NULL, source_acl_healthy INTEGER NOT NULL DEFAULT 0)")
        binding_columns = {str(row[1]) for row in self.db.execute("PRAGMA table_info(bound_applications)")}
        if "source_acl_healthy" not in binding_columns:
            self.db.execute("ALTER TABLE bound_applications ADD COLUMN source_acl_healthy INTEGER NOT NULL DEFAULT 0")
        # A process restart invalidates previously recorded source health.
        # Re-enable Protect only after fresh authenticated control-plane sync.
        self.db.execute("UPDATE bound_applications SET source_acl_healthy=0 WHERE mode='protect'")
        self.db.execute("CREATE TABLE IF NOT EXISTS request_contexts (decision_id TEXT PRIMARY KEY, application_id TEXT NOT NULL, subject_id TEXT NOT NULL, request_id TEXT NOT NULL DEFAULT '', resources_json TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT)")
        self.db.execute("CREATE TABLE IF NOT EXISTS audit_buffer (event_id TEXT PRIMARY KEY, decision_id TEXT, application_id TEXT NOT NULL, subject_id TEXT NOT NULL, request_id TEXT NOT NULL, layer TEXT NOT NULL DEFAULT 'layer1', result TEXT NOT NULL, reason TEXT NOT NULL, policy_version INTEGER NOT NULL, resources_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL, delivered_at TEXT)")
        self.max_audit_records = max(1, max_audit_records)
        columns = {str(row[1]) for row in self.db.execute("PRAGMA table_info(request_contexts)")}
        if "request_id" not in columns:
            self.db.execute("ALTER TABLE request_contexts ADD COLUMN request_id TEXT NOT NULL DEFAULT ''")
        if "consumed_at" not in columns:
            self.db.execute("ALTER TABLE request_contexts ADD COLUMN consumed_at TEXT")
        audit_columns = {str(row[1]) for row in self.db.execute("PRAGMA table_info(audit_buffer)")}
        for name, declaration in (("decision_id", "TEXT"), ("layer", "TEXT NOT NULL DEFAULT 'layer1'"), ("resources_json", "TEXT NOT NULL DEFAULT '[]'")):
            if name not in audit_columns:
                self.db.execute(f"ALTER TABLE audit_buffer ADD COLUMN {name} {declaration}")
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
                    # The envelope revision can contain delayed, duplicated, or
                    # reordered per-resource events. Preserve the actual event
                    # version; otherwise an older ALLOW in a newer envelope
                    # could overwrite an effective DENY.
                    row_version = row.get("version", version)
                    if (not isinstance(row_version, int) or isinstance(row_version, bool)
                            or row_version < 1 or row_version > version):
                        raise ValueError("INVALID_POLICY_VERSION")
                    decision = str(row["decision"])
                    if decision not in {"allow", "deny", "unknown"}:
                        raise ValueError("INVALID_POLICY_DECISION")
                    self.db.execute(
                        "INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?, ?) "
                        "ON CONFLICT(subject_id, source_id, resource_id, scope) "
                        "DO UPDATE SET decision=excluded.decision, "
                        "reason=excluded.reason, version=excluded.version "
                        "WHERE excluded.version > decisions.version "
                        "OR (excluded.version = decisions.version AND "
                        "CASE excluded.decision WHEN 'deny' THEN 2 "
                        "WHEN 'unknown' THEN 1 ELSE 0 END > "
                        "CASE decisions.decision WHEN 'deny' THEN 2 "
                        "WHEN 'unknown' THEN 1 ELSE 0 END)",
                        (str(row["subject_id"]), str(row["source_id"]),
                         str(row["resource_id"]), str(row.get("scope", "read")),
                         decision, str(row.get("reason", "effective_access")), row_version),
                    )
                self.db.execute("INSERT INTO metadata VALUES ('version', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(version),))
        return True

    def version(self) -> int:
        with self._lock:
            row = self.db.execute("SELECT value FROM metadata WHERE key='version'").fetchone()
        return int(row[0]) if row else 0

    def set_application_bindings(self, applications: list[dict[str, str]]) -> None:
        """Atomically replace authoritative bindings on every Guard sync poll.

        An empty list is meaningful: the Guard is not authorized to serve any
        applications until explicitly assigned by the control plane.
        """
        validated: list[tuple[str, str, str, int]] = []
        for item in applications:
            application_id = item.get("application_id")
            source_id = item.get("source_id")
            mode = item.get("mode")
            if not application_id or not source_id or mode not in {"shadow", "protect"}:
                raise ValueError("INVALID_APPLICATION_BINDINGS")
            health = item.get("source_acl_healthy", True)
            if not isinstance(health, bool):
                raise ValueError("INVALID_SOURCE_ACL_HEALTH")
            validated.append((application_id, source_id, mode, int(health)))
        with self._lock:
            with self.db:
                self.db.execute("DELETE FROM bound_applications")
                self.db.executemany(
                    "INSERT INTO bound_applications (application_id, source_id, mode, source_acl_healthy) VALUES (?, ?, ?, ?)",
                    validated,
                )
                self.db.execute("INSERT INTO metadata (key, value) VALUES ('applications_synced', '1') ON CONFLICT(key) DO UPDATE SET value='1'")

    def mark_sync_success(self) -> None:
        """Record the last successful trusted control-plane policy poll."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self.db:
                self.db.execute(
                    "INSERT INTO metadata (key, value) VALUES ('last_policy_sync', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (now,),
                )

    def sync_age_seconds(self) -> float | None:
        with self._lock:
            row = self.db.execute(
                "SELECT value FROM metadata WHERE key='last_policy_sync'"
            ).fetchone()
        if not row:
            return None
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(str(row[0]))).total_seconds()
        except ValueError:
            return None
        return max(0.0, age)

    def application_bindings_received(self) -> bool:
        with self._lock:
            return self.db.execute("SELECT 1 FROM metadata WHERE key='applications_synced'").fetchone() is not None

    def application_modes(self) -> dict[str, str]:
        """Report the modes actually installed by trusted Guard synchronization."""
        with self._lock:
            rows = self.db.execute(
                "SELECT application_id, mode FROM bound_applications"
            ).fetchall()
        return {str(app_id): str(active_mode) for app_id, active_mode in rows}

    def application_binding(self, application_id: str) -> tuple[str, str] | None:
        """Return (source_id, mode) from a trusted control-plane snapshot."""
        with self._lock:
            row = self.db.execute(
                "SELECT source_id, mode FROM bound_applications WHERE application_id=?",
                (application_id,),
            ).fetchone()
        return (str(row[0]), str(row[1])) if row else None

    def all_protect_sources_healthy(self) -> bool:
        """Machine readiness must reflect upstream ACL/directory health."""
        with self._lock:
            row = self.db.execute(
                "SELECT 1 FROM bound_applications WHERE mode='protect' "
                "AND source_acl_healthy=0 LIMIT 1"
            ).fetchone()
        return row is None

    def source_acl_healthy(self, application_id: str) -> bool:
        with self._lock:
            row = self.db.execute(
                "SELECT source_acl_healthy FROM bound_applications WHERE application_id=?",
                (application_id,),
            ).fetchone()
        return row is not None and bool(row[0])

    def decide(self, subject_id: str, source_id: str, resource_id: str, scope: str) -> tuple[str, str]:
        with self._lock:
            row = self.db.execute("SELECT decision, reason FROM decisions WHERE subject_id=? AND source_id=? AND resource_id=? AND scope=?", (subject_id, source_id, resource_id, scope)).fetchone()
        return (str(row[0]), str(row[1])) if row else ("unknown", "POLICY_MISSING")

    def save_context(self, decision_id: str, application_id: str, subject_id: str, resource_ids: list[str], *, request_id: str = "", ttl_seconds: int = 300) -> None:
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()
        with self._lock:
            with self.db:
                self.db.execute("DELETE FROM request_contexts WHERE expires_at < ?", (datetime.now(timezone.utc).isoformat(),))
                self.db.execute("INSERT INTO request_contexts (decision_id, application_id, subject_id, request_id, resources_json, expires_at, consumed_at) VALUES (?, ?, ?, ?, ?, ?, NULL)", (decision_id, application_id, subject_id, request_id, json.dumps(sorted(set(resource_ids))), expires_at))

    def load_context(self, decision_id: str, application_id: str, subject_id: str, request_id: str = "") -> set[str] | None:
        with self._lock:
            row = self.db.execute("SELECT resources_json, expires_at, consumed_at FROM request_contexts WHERE decision_id=? AND application_id=? AND subject_id=? AND request_id=?", (decision_id, application_id, subject_id, request_id)).fetchone()
        if not row or row[2] is not None or str(row[1]) < datetime.now(timezone.utc).isoformat():
            return None
        return set(json.loads(str(row[0])))

    def consume_contexts_with_recheck(
        self, decision_ids: list[str], application_id: str, subject_id: str,
        request_id: str, *, source_id: str, expected_mode: str,
    ) -> str:
        """Atomically reauthorize and consume Layer 1 contexts at Layer 2 release.

        The policy synchronizer uses the same lock. An IMMEDIATE SQLite
        transaction also serializes with other writer connections, so a deny
        cannot commit between our final authorization read and consumption.
        Returns 'ok', 'invalid', or 'revoked'.
        """
        if not decision_ids or len(decision_ids) != len(set(decision_ids)) or len(decision_ids) > 17:
            return "invalid"
        now = datetime.now(timezone.utc).isoformat()
        placeholders = ",".join("?" for _ in decision_ids)
        with self._lock:
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                rows = self.db.execute(
                    f"SELECT decision_id, resources_json FROM request_contexts "
                    f"WHERE decision_id IN ({placeholders}) "
                    "AND application_id=? AND subject_id=? AND request_id=? "
                    "AND consumed_at IS NULL AND expires_at>=?",
                    (*decision_ids, application_id, subject_id, request_id, now),
                ).fetchall()
                if len(rows) != len(decision_ids):
                    return "invalid"
                binding = self.db.execute(
                    "SELECT source_id, mode, source_acl_healthy FROM bound_applications "
                    "WHERE application_id=?", (application_id,),
                ).fetchone()
                if not binding or binding[0] != source_id or binding[1] != expected_mode:
                    return "invalid"
                if expected_mode == "protect" and not binding[2]:
                    return "revoked"
                resource_ids = set()
                try:
                    for _, encoded in rows:
                        values = json.loads(str(encoded))
                        if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
                            return "invalid"
                        resource_ids.update(values)
                except (ValueError, TypeError):
                    return "invalid"
                revoked = False
                for rid in resource_ids if expected_mode == "protect" else ():
                    decision = self.db.execute(
                        "SELECT decision FROM decisions WHERE subject_id=? "
                        "AND source_id=? AND resource_id=? AND scope='read'",
                        (subject_id, source_id, rid),
                    ).fetchone()
                    if decision is None or decision[0] != "allow":
                        revoked = True
                        break
                updated = self.db.execute(
                    f"UPDATE request_contexts SET consumed_at=? "
                    f"WHERE decision_id IN ({placeholders}) "
                    "AND application_id=? AND subject_id=? AND request_id=? "
                    "AND consumed_at IS NULL AND expires_at>=?",
                    (now, *decision_ids, application_id, subject_id, request_id, now),
                )
                if updated.rowcount != len(decision_ids):
                    return "invalid"
                return "revoked" if revoked else "ok"

    def consume_context(self, decision_id: str, application_id: str, subject_id: str, request_id: str) -> bool:
        """Mark an exact Layer 1 context one-time-use after Layer 2 evaluates it."""
        return self.consume_contexts([decision_id], application_id, subject_id, request_id)

    def consume_contexts(
        self, decision_ids: list[str], application_id: str, subject_id: str,
        request_id: str, *, expected_policy_version: int | None = None,
    ) -> bool:
        """Consume contexts only if the checked policy remains current."""
        if not decision_ids or len(decision_ids) != len(set(decision_ids)) or len(decision_ids) > 17:
            return False
        now = datetime.now(timezone.utc).isoformat()
        placeholders = ",".join("?" for _ in decision_ids)
        with self._lock:
            if expected_policy_version is not None and self.version() != expected_policy_version:
                return False
            with self.db:
                rows = self.db.execute(
                    f"SELECT decision_id FROM request_contexts WHERE decision_id IN ({placeholders}) "
                    "AND application_id=? AND subject_id=? AND request_id=? "
                    "AND consumed_at IS NULL AND expires_at>=?",
                    (*decision_ids, application_id, subject_id, request_id, now),
                ).fetchall()
                if len(rows) != len(decision_ids):
                    return False
                updated = self.db.execute(
                    f"UPDATE request_contexts SET consumed_at=? WHERE decision_id IN ({placeholders}) "
                    "AND application_id=? AND subject_id=? AND request_id=? "
                    "AND consumed_at IS NULL AND expires_at>=?",
                    (now, *decision_ids, application_id, subject_id, request_id, now),
                )
                if updated.rowcount != len(decision_ids):
                    raise RuntimeError("CONTEXT_CONSUMPTION_CONFLICT")
                return True

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
        decision_id: str | None = None,
        layer: str = "layer1",
        resource_ids: list[str] | None = None,
    ) -> bool:
        """Persist only decision metadata. Raw prompts, documents, and output are never stored."""
        with self._lock:
            with self.db:
                inserted = self.db.execute(
                    "INSERT OR IGNORE INTO audit_buffer (event_id, decision_id, application_id, subject_id, request_id, layer, result, reason, policy_version, resources_json, created_at, delivered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                    (event_id, decision_id, application_id, subject_id, request_id, layer, result, reason, policy_version, json.dumps(sorted(set(resource_ids or []))), datetime.now(timezone.utc).isoformat()),
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
                "SELECT event_id, decision_id, application_id, subject_id, request_id, layer, result, reason, policy_version, resources_json FROM audit_buffer WHERE delivered_at IS NULL ORDER BY created_at ASC LIMIT ?",
                (max(1, min(limit, 100)),),
            ).fetchall()
        result: list[dict[str, object]] = []
        for row in rows:
            item: dict[str, object] = {"event_id": row[0], "application_id": row[2], "subject_id": row[3], "request_id": row[4], "result": row[6], "reason": row[7], "policy_version": row[8]}
            # Preserve the compact legacy envelope when optional provenance is absent.
            if row[1] is not None:
                item["decision_id"] = row[1]
            if str(row[5]) != "layer1":
                item["layer"] = row[5]
            resources = json.loads(str(row[9]))
            if resources:
                item["resource_ids"] = resources
            result.append(item)
        return result

    def mark_audit_delivered(self, event_ids: list[str]) -> None:
        if not event_ids:
            return
        with self._lock:
            with self.db:
                self.db.executemany(
                    "UPDATE audit_buffer SET delivered_at=? WHERE event_id=? AND delivered_at IS NULL",
                    [(datetime.now(timezone.utc).isoformat(), event_id) for event_id in event_ids],
                )
