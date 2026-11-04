"""Fail-closed source-qualified authorization protocol for multi-source RAG.

V2 contexts cannot be interpreted by the legacy V1 (resource-id-only) path.
All source identity, policy, revision and one-time release checks share the
PolicyCache SQLite transaction/lock. Only authoritative Guard snapshots install
application/source bindings.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from .cache import PolicyCache

V2_SOURCE_SENTINEL = "__accessproof_multisource_v2__"


def principal_key(subject: str, issuer: str, tenant: str | None) -> str:
    """Bind requests to all three verified immutable JWT identity components."""
    encoded = json.dumps([issuer, tenant or "", subject], separators=(",", ":"))
    return "v2:" + hashlib.sha256(encoded.encode()).hexdigest()


def _resource_key(item: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(item["source_id"]), str(item["resource_id"]),
        str(item.get("chunk_id") or ""), str(item.get("content_version") or ""),
    )


class MultiSourceGuard:
    def __init__(self, cache: PolicyCache):
        self.cache = cache

    def filter(
        self, *, application_id: str, request_id: str, principal: str,
        mapped_subjects: dict[str, str], resources: list[dict[str, Any]],
    ) -> dict[str, Any]:
        cache = self.cache
        now = datetime.now(timezone.utc)
        with cache._lock:
            # This write lock also serializes policy/identity installations.
            with cache._write_transaction():
                bindings = cache.application_sources(application_id)
                if not bindings or not mapped_subjects or any(
                    source not in bindings for source in mapped_subjects
                ):
                    return {"decision": "block", "reason": "APPLICATION_SOURCE_MISMATCH"}
                binding = cache.application_binding(application_id)
                if binding is None:
                    return {"decision": "block", "reason": "APPLICATION_NOT_BOUND"}
                mode = binding[1]
                if mode != "protect":
                    return {"decision": "block", "reason": "PROTECT_MODE_REQUIRED"}
                if any(not bindings[src] for src in mapped_subjects):
                    return {"decision": "block", "reason": "SOURCE_ACL_STALE"}
                if not cache.authorization_revisions_received():
                    return {"decision": "block", "reason": "AUTHORIZATION_REVISION_NOT_SYNCED"}
                revision = cache.authorization_revision(application_id)
                if revision is None:
                    return {"decision": "block", "reason": "AUTHORIZATION_REVISION_MISSING"}
                allowed: list[dict[str, Any]] = []
                denied: list[dict[str, Any]] = []
                seen: set[tuple[str, str, str]] = set()
                for item in resources:
                    source, resource, chunk, version = _resource_key(item)
                    if source not in mapped_subjects:
                        return {"decision": "block", "reason": "APPLICATION_SOURCE_MISMATCH"}
                    key = (source, resource, chunk)
                    # Also reject conflicting versions of the same chunk.
                    if key in seen:
                        return {"decision": "block", "reason": "DUPLICATE_RESOURCE"}
                    seen.add(key)
                    source_subject = mapped_subjects[source]
                    decision, reason = cache.decide(source_subject, source, resource, "read")
                    if decision == "allow":
                        stale = cache.content_version_refusal(source, resource, [version or None])
                        if stale:
                            decision, reason = "deny", stale
                    entry = {
                        "source_id": source, "resource_id": resource,
                        "chunk_ids": [chunk] if chunk else [], "reason": reason,
                        "content_version": version,
                    }
                    (allowed if decision == "allow" else denied).append(entry)
                if not allowed:
                    return {
                        "decision": "block", "reason": "NO_AUTHORIZED_RESOURCES",
                        "mode": "protect", "allowed": [], "denied": denied,
                    }
                decision_id = str(uuid4())
                # Context is source-qualified, includes the exact source principal
                # and is unusable through V1: sentinel + principal hash.
                context = [
                    {**entry, "source_subject": mapped_subjects[entry["source_id"]]}
                    for entry in allowed
                ]
                cache.db.execute(
                    "INSERT INTO request_contexts "
                    "(decision_id, application_id, subject_id, request_id, resources_json, "
                    "expires_at, consumed_at, source_id, revision_hash) "
                    "VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)",
                    (
                        decision_id, application_id, principal, request_id,
                        json.dumps(context, sort_keys=True),
                        (now + timedelta(minutes=5)).isoformat(),
                        V2_SOURCE_SENTINEL, revision[1],
                    ),
                )
                return {
                    "decision_id": decision_id, "decision": "allow", "mode": "protect",
                    "reason": "SOURCE_SCOPED_ACCESS", "policy_version": cache.version(),
                    "allowed": allowed, "denied": denied,
                    "authorization_revision": revision[0],
                    "authorization_revision_hash": revision[1],
                }

    def release(
        self, *, application_id: str, request_id: str, principal: str,
        decision_id: str, mapped_subjects: dict[str, str],
        used_resources: list[dict[str, Any]], provenance: list[dict[str, Any]],
    ) -> dict[str, Any]:
        cache = self.cache
        now = datetime.now(timezone.utc).isoformat()
        with cache._lock:
            with cache._write_transaction():
                # Serialize across multiple SQLite connections and policy commits.
                cache.db.execute("BEGIN IMMEDIATE")
                def deny(reason: str) -> dict[str, Any]:
                    return {
                        "decision": "block", "reason": reason,
                        "policy_version": cache.version(),
                    }

                row = cache.db.execute(
                    "SELECT resources_json, revision_hash FROM request_contexts "
                    "WHERE decision_id=? AND application_id=? AND subject_id=? "
                    "AND request_id=? AND consumed_at IS NULL AND expires_at>=? "
                    "AND source_id=?",
                    (
                        decision_id, application_id, principal, request_id,
                        now, V2_SOURCE_SENTINEL,
                    ),
                ).fetchone()
                if row is None:
                    return deny("DECISION_CONTEXT_INVALID")
                # Even unsuccessful checks consume the context, preventing retries
                # from turning an earlier denial into a later release.
                cursor = cache.db.execute(
                    "UPDATE request_contexts SET consumed_at=? WHERE decision_id=? "
                    "AND consumed_at IS NULL", (now, decision_id),
                )
                if cursor.rowcount != 1:
                    return deny("DECISION_CONTEXT_INVALID")
                binding = cache.application_binding(application_id)
                if binding is None or binding[1] != "protect":
                    return deny("PROTECT_MODE_REQUIRED")
                sources = cache.application_sources(application_id)
                current = cache.authorization_revision(application_id)
                if current is None or str(row[1]) != current[1]:
                    return deny("AUTHORIZATION_REVISION_CHANGED")
                try:
                    stored = json.loads(str(row[0]))
                    if not isinstance(stored, list) or not stored:
                        return deny("DECISION_CONTEXT_INVALID")
                    permitted = {
                        (src, rid, str(chunk), str(version))
                        for item in stored
                        for src, rid, chunk, version in [(
                            item["source_id"], item["resource_id"],
                            (item.get("chunk_ids") or [""])[0],
                        item.get("content_version") or "",
                        )]
                    }
                    used = {_resource_key(entry) for entry in used_resources}
                    traced = {_resource_key(entry) for entry in provenance}
                except (TypeError, ValueError, KeyError, IndexError):
                    return deny("PROVENANCE_INVALID")
                if (
                    not used or len(used) != len(used_resources)
                    or used != traced or len(traced) != len(provenance)
                    or not used.issubset(permitted)
                ):
                    return deny("PROVENANCE_ESCAPE")
                for item in stored:
                    source, resource, _, _ = _resource_key(item)
                    if source not in sources or not sources[source]:
                        return deny("SOURCE_ACL_STALE")
                    if mapped_subjects.get(source) != item.get("source_subject"):
                        return deny("IDENTITY_MAPPING_CHANGED")
                    decision, _ = cache.decide(
                        item["source_subject"], source, resource, "read"
                    )
                    if decision != "allow":
                        return deny("LAYER2_ACCESS_REVOKED")
                return {
                    "decision": "allow", "reason": "MULTISOURCE_PROVENANCE_VALID",
                    "policy_version": cache.version(),
                    "authorization_revision": current[0],
                    "authorization_revision_hash": current[1],
                }
