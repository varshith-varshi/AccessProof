from __future__ import annotations

import sqlite3
import json
from threading import RLock
from datetime import datetime, timedelta, timezone
from pathlib import Path


class AuditBufferFull(RuntimeError):
    """Security audit evidence would be lost if another event were accepted."""


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
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS identity_mappings "
            "(source_id TEXT NOT NULL, issuer TEXT NOT NULL, subject TEXT NOT NULL, "
            "tenant_id TEXT NOT NULL DEFAULT '', source_subject_id TEXT NOT NULL, "
            "PRIMARY KEY(source_id, issuer, subject, tenant_id))"
        )
        binding_columns = {str(row[1]) for row in self.db.execute("PRAGMA table_info(bound_applications)")}
        if "source_acl_healthy" not in binding_columns:
            self.db.execute("ALTER TABLE bound_applications ADD COLUMN source_acl_healthy INTEGER NOT NULL DEFAULT 0")
        # A process restart invalidates previously recorded source health.
        # Re-enable Protect only after fresh authenticated control-plane sync.
        self.db.execute("UPDATE bound_applications SET source_acl_healthy=0 WHERE mode='protect'")
        self.db.execute("CREATE TABLE IF NOT EXISTS request_contexts (decision_id TEXT PRIMARY KEY, application_id TEXT NOT NULL, subject_id TEXT NOT NULL, request_id TEXT NOT NULL DEFAULT '', resources_json TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT, revision_hash TEXT NOT NULL DEFAULT '')")
        self.db.execute("CREATE TABLE IF NOT EXISTS authorization_revisions (application_id TEXT PRIMARY KEY, revision INTEGER NOT NULL, revision_hash TEXT NOT NULL, generated_at TEXT NOT NULL, installed_at TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS audit_buffer (event_id TEXT PRIMARY KEY, decision_id TEXT, application_id TEXT NOT NULL, subject_id TEXT NOT NULL, request_id TEXT NOT NULL, layer TEXT NOT NULL DEFAULT 'layer1', result TEXT NOT NULL, reason TEXT NOT NULL, policy_version INTEGER NOT NULL, resources_json TEXT NOT NULL DEFAULT '[]', authorization_revision INTEGER, authorization_revision_hash TEXT, created_at TEXT NOT NULL, delivered_at TEXT)")
        self.max_audit_records = max(1, max_audit_records)
        columns = {str(row[1]) for row in self.db.execute("PRAGMA table_info(request_contexts)")}
        if "request_id" not in columns:
            self.db.execute("ALTER TABLE request_contexts ADD COLUMN request_id TEXT NOT NULL DEFAULT ''")
        if "consumed_at" not in columns:
            self.db.execute("ALTER TABLE request_contexts ADD COLUMN consumed_at TEXT")
        # Old in-flight contexts intentionally become invalid for bound apps:
        # an empty source cannot authenticate provenance for a newer binding.
        if "source_id" not in columns:
            self.db.execute("ALTER TABLE request_contexts ADD COLUMN source_id TEXT NOT NULL DEFAULT ''")
        if "revision_hash" not in columns:
            self.db.execute("ALTER TABLE request_contexts ADD COLUMN revision_hash TEXT NOT NULL DEFAULT ''")
        audit_columns = {str(row[1]) for row in self.db.execute("PRAGMA table_info(audit_buffer)")}
        for name, declaration in (
            ("decision_id", "TEXT"), ("layer", "TEXT NOT NULL DEFAULT 'layer1'"),
            ("resources_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("authorization_revision", "INTEGER"),
            ("authorization_revision_hash", "TEXT"),
        ):
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
                    # Never coerce malformed upstream principals or resource
                    # identifiers into a string. str(None) or str(1) can collide
                    # with a real provider identity and forge an allow grant.
                    for field in ("subject_id", "source_id", "resource_id", "scope"):
                        value = row.get("scope", "read") if field == "scope" else row[field]
                        if not isinstance(value, str) or not value.strip():
                            raise ValueError("INVALID_POLICY_IDENTIFIER")
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

    def set_application_bindings(self, applications: list[dict[str, object]]) -> None:
        """Atomically replace authoritative bindings on every Guard sync poll.

        An empty list is meaningful: the Guard is not authorized to serve any
        applications until explicitly assigned by the control plane.
        """
        validated: list[tuple[str, str, str, int]] = []
        for item in applications:
            application_id = item.get("application_id")
            source_id = item.get("source_id")
            mode = item.get("mode")
            if (
                not isinstance(application_id, str)
                or not application_id
                or not isinstance(source_id, str)
                or not source_id
                or mode not in {"shadow", "protect"}
            ):
                raise ValueError("INVALID_APPLICATION_BINDINGS")
            # Missing source-health evidence is UNKNOWN, never healthy.
            # This cache-level check also protects future sync/adapter callers.
            health = item.get("source_acl_healthy", False)
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

    def set_authorization_revisions(self, revisions: list[dict[str, object]]) -> None:
        """Install a monotonic signed-revision snapshot for bound applications.

        Revisions may only advance. A same-number/different-hash value is a
        fork and is rejected rather than silently replacing local evidence.
        """
        validated: dict[str, tuple[int, str, str]] = {}
        for item in revisions:
            application_id = item.get("application_id")
            revision = item.get("revision")
            revision_hash = item.get("revision_hash")
            generated_at = item.get("generated_at", "")
            if (
                not isinstance(application_id, str) or not application_id
                or not isinstance(revision, int) or isinstance(revision, bool) or revision < 1
                or not isinstance(revision_hash, str) or len(revision_hash) != 64
                or any(char not in "0123456789abcdef" for char in revision_hash)
                or not isinstance(generated_at, str)
            ):
                raise ValueError("INVALID_AUTHORIZATION_REVISION")
            if application_id in validated:
                raise ValueError("DUPLICATE_AUTHORIZATION_REVISION")
            validated[application_id] = (revision, revision_hash, generated_at)
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self.db:
                existing = {
                    str(row[0]): (int(row[1]), str(row[2]))
                    for row in self.db.execute(
                        "SELECT application_id, revision, revision_hash FROM authorization_revisions"
                    )
                }
                for application_id, (revision, revision_hash, _) in validated.items():
                    current = existing.get(application_id)
                    if current is not None:
                        if revision < current[0]:
                            raise ValueError("STALE_AUTHORIZATION_REVISION")
                        if revision == current[0] and revision_hash != current[1]:
                            raise ValueError("AUTHORIZATION_REVISION_FORK")
                self.db.execute("DELETE FROM authorization_revisions")
                self.db.executemany(
                    "INSERT INTO authorization_revisions "
                    "(application_id, revision, revision_hash, generated_at, installed_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    [
                        (application_id, revision, revision_hash, generated_at, now)
                        for application_id, (revision, revision_hash, generated_at) in validated.items()
                    ],
                )
                self.db.execute(
                    "INSERT INTO metadata (key, value) VALUES ('authorization_revisions_synced', '1') "
                    "ON CONFLICT(key) DO UPDATE SET value='1'"
                )

    def authorization_revision(self, application_id: str) -> tuple[int, str] | None:
        with self._lock:
            row = self.db.execute(
                "SELECT revision, revision_hash FROM authorization_revisions WHERE application_id=?",
                (application_id,),
            ).fetchone()
        return (int(row[0]), str(row[1])) if row else None

    def authorization_revision_snapshot(self) -> dict[str, dict[str, object]]:
        """Report only installed revisions; this is evidence, never authority."""
        with self._lock:
            rows = self.db.execute(
                "SELECT application_id, revision, revision_hash FROM authorization_revisions "
                "ORDER BY application_id LIMIT 100"
            ).fetchall()
        return {
            str(row[0]): {"revision": int(row[1]), "revision_hash": str(row[2])}
            for row in rows
        }

    def authorization_revisions_received(self) -> bool:
        with self._lock:
            return self.db.execute(
                "SELECT 1 FROM metadata WHERE key='authorization_revisions_synced'"
            ).fetchone() is not None

    def all_protect_revisions_present(self) -> bool:
        """A Protect binding without a current revision is not ready."""
        with self._lock:
            row = self.db.execute(
                "SELECT 1 FROM bound_applications b LEFT JOIN authorization_revisions r "
                "ON r.application_id=b.application_id "
                "WHERE b.mode='protect' AND r.application_id IS NULL LIMIT 1"
            ).fetchone()
        return row is None

    def set_identity_mappings(self, mappings: list[dict[str, object]]) -> None:
        """Atomically replace verified mappings received over Guard sync.

        Any omitted, suspended, revoked or conflicting mapping disappears from
        the local authorization boundary on the next authenticated poll.
        """
        validated: list[tuple[str, str, str, str, str]] = []
        seen: set[tuple[str, str, str, str]] = set()
        for item in mappings:
            source_id = item.get("source_id")
            issuer = item.get("issuer")
            subject = item.get("subject")
            tenant_id = item.get("tenant_id", "")
            source_subject_id = item.get("source_subject_id")
            if not all(isinstance(value, str) and value for value in (source_id, issuer, subject, source_subject_id)):
                raise ValueError("INVALID_IDENTITY_MAPPINGS")
            assert isinstance(source_id, str) and isinstance(issuer, str) and isinstance(subject, str)
            assert isinstance(source_subject_id, str)
            if tenant_id is None:
                tenant_id = ""
            if not isinstance(tenant_id, str):
                raise ValueError("INVALID_IDENTITY_MAPPINGS")
            key = (source_id, issuer, subject, tenant_id)
            if key in seen:
                raise ValueError("CONFLICTING_IDENTITY_MAPPINGS")
            seen.add(key)
            validated.append((source_id, issuer, subject, tenant_id, source_subject_id))
        with self._lock:
            with self.db:
                self.db.execute("DELETE FROM identity_mappings")
                self.db.executemany(
                    "INSERT INTO identity_mappings (source_id, issuer, subject, tenant_id, source_subject_id) VALUES (?, ?, ?, ?, ?)",
                    validated,
                )
                self.db.execute("INSERT INTO metadata (key, value) VALUES ('identity_mappings_synced', '1') ON CONFLICT(key) DO UPDATE SET value='1'")

    def resolve_identity(self, source_id: str, issuer: str, subject: str, tenant_id: str | None) -> str | None:
        """Resolve only an exact, currently synced verified principal mapping."""
        with self._lock:
            row = self.db.execute(
                "SELECT source_subject_id FROM identity_mappings WHERE source_id=? AND issuer=? AND subject=? AND tenant_id=?",
                (source_id, issuer, subject, tenant_id or ""),
            ).fetchone()
        return str(row[0]) if row else None

    def identity_mappings_received(self) -> bool:
        with self._lock:
            return self.db.execute("SELECT 1 FROM metadata WHERE key='identity_mappings_synced'").fetchone() is not None

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
        # A persisted timestamp in the future can result from a host-clock
        # rollback, VM snapshot restoration, or unexpected state corruption.
        # Clamping it to zero made an old policy look perpetually fresh until
        # wall time caught up. Unknown clock freshness must fail closed.
        return age if age >= 0 else None

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

    def allowed_resources(
        self, subject_id: str, source_id: str, *, scope: str = "read", limit: int = 20_000,
    ) -> tuple[list[str], bool]:
        """Enumerate explicit ALLOW resources for a verified subject and source.

        This returns identifiers only, never document content. ``truncated`` is
        True when the bound was exceeded; callers must treat that as an
        incomplete scope rather than searching a silently partial authorization
        set, which starves users of documents they are entitled to receive.
        """
        if not 1 <= limit <= 20_000:
            raise ValueError("INVALID_SCOPE_LIMIT")
        with self._lock:
            rows = self.db.execute(
                "SELECT resource_id FROM decisions "
                "WHERE subject_id=? AND source_id=? AND scope=? AND decision='allow' "
                "ORDER BY resource_id LIMIT ?",
                (subject_id, source_id, scope, limit + 1),
            ).fetchall()
        values = [str(row[0]) for row in rows]
        return values[:limit], len(values) > limit

    def decide(self, subject_id: str, source_id: str, resource_id: str, scope: str) -> tuple[str, str]:
        with self._lock:
            row = self.db.execute("SELECT decision, reason FROM decisions WHERE subject_id=? AND source_id=? AND resource_id=? AND scope=?", (subject_id, source_id, resource_id, scope)).fetchone()
        return (str(row[0]), str(row[1])) if row else ("unknown", "POLICY_MISSING")

    def save_context(self, decision_id: str, application_id: str, subject_id: str, resource_ids: list[str], *, request_id: str = "", source_id: str = "", revision_hash: str = "", ttl_seconds: int = 300) -> None:
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()
        with self._lock:
            with self.db:
                self.db.execute("DELETE FROM request_contexts WHERE expires_at < ?", (datetime.now(timezone.utc).isoformat(),))
                self.db.execute("INSERT INTO request_contexts (decision_id, application_id, subject_id, request_id, resources_json, expires_at, consumed_at, source_id, revision_hash) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)", (decision_id, application_id, subject_id, request_id, json.dumps(sorted(set(resource_ids))), expires_at, source_id, revision_hash))

    def load_context_binding(self, decision_id: str, application_id: str, subject_id: str, request_id: str = "", *, source_id: str | None = None) -> tuple[set[str], str] | None:
        with self._lock:
            row = self.db.execute("SELECT resources_json, expires_at, consumed_at, source_id, revision_hash FROM request_contexts WHERE decision_id=? AND application_id=? AND subject_id=? AND request_id=?", (decision_id, application_id, subject_id, request_id)).fetchone()
        if not row or row[2] is not None or str(row[1]) < datetime.now(timezone.utc).isoformat():
            return None
        if source_id is not None and row[3] != source_id:
            return None
        return set(json.loads(str(row[0]))), str(row[4] or "")

    def load_context(self, decision_id: str, application_id: str, subject_id: str, request_id: str = "", *, source_id: str | None = None) -> set[str] | None:
        loaded = self.load_context_binding(
            decision_id, application_id, subject_id, request_id, source_id=source_id,
        )
        return loaded[0] if loaded is not None else None

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
                    f"SELECT decision_id, resources_json, source_id, revision_hash FROM request_contexts "
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
                if expected_mode == "protect" and self.authorization_revisions_received():
                    current = self.authorization_revision(application_id)
                    if current is None:
                        return "revision_changed"
                    for _, _, _, context_revision in rows:
                        if str(context_revision or "") != current[1]:
                            return "revision_changed"
                resource_ids = set()
                try:
                    for _, encoded, context_source, _ in rows:
                        if context_source != source_id:
                            return "invalid"
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
        authorization_revision: int | None = None,
        authorization_revision_hash: str | None = None,
    ) -> bool:
        """Persist only decision metadata. Raw prompts, documents, and output are never stored."""
        with self._lock:
            with self.db:
                inserted = self.db.execute(
                    "INSERT OR IGNORE INTO audit_buffer (event_id, decision_id, application_id, subject_id, request_id, layer, result, reason, policy_version, resources_json, authorization_revision, authorization_revision_hash, created_at, delivered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                    (event_id, decision_id, application_id, subject_id, request_id, layer, result, reason, policy_version, json.dumps(sorted(set(resource_ids or []))), authorization_revision, authorization_revision_hash, datetime.now(timezone.utc).isoformat()),
                ).rowcount > 0
                overflow = self.db.execute("SELECT COUNT(*) FROM audit_buffer").fetchone()[0] - self.max_audit_records
                if overflow > 0:
                    # A long control-plane outage must NEVER silently erase pending
                    # authorization evidence. Discard only acknowledged records.
                    self.db.execute(
                        "DELETE FROM audit_buffer WHERE event_id IN "
                        "(SELECT event_id FROM audit_buffer WHERE delivered_at IS NOT NULL "
                        "ORDER BY created_at ASC LIMIT ?)",
                        (overflow,),
                    )
                    remaining = self.db.execute("SELECT COUNT(*) FROM audit_buffer").fetchone()[0]
                    if remaining > self.max_audit_records:
                        # Rolling back this transaction also removes the new event;
                        # protected requests fail closed until audit upload resumes.
                        raise AuditBufferFull("AUDIT_BUFFER_FULL")
        return inserted

    def audit_has_capacity(self) -> bool:
        """Whether a new event can be retained without discarding pending records."""
        with self._lock:
            pending = int(self.db.execute(
                "SELECT COUNT(*) FROM audit_buffer WHERE delivered_at IS NULL"
            ).fetchone()[0])
        return pending < self.max_audit_records

    def pending_audit(self, limit: int = 100) -> list[dict[str, object]]:
        with self._lock:
            rows = self.db.execute(
                "SELECT event_id, decision_id, application_id, subject_id, request_id, layer, result, reason, policy_version, resources_json, authorization_revision, authorization_revision_hash, created_at FROM audit_buffer WHERE delivered_at IS NULL ORDER BY created_at ASC LIMIT ?",
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
            if row[10] is not None and row[11] is not None:
                item["authorization_revision"] = int(row[10])
                item["authorization_revision_hash"] = str(row[11])
                item["occurred_at"] = row[12]
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
