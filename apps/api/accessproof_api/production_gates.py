"""SharePoint Production Protect certification gates (mission Part 27).

Evaluates gates A–J for ONE organization + application from the system's own
evidence. It never trusts a dashboard label, a mode flag or a feature flag.
Every gate is PASS, FAIL or BLOCKED; anything not proven is not PASS.

Even when every technical gate passes, the verdict is
``TECHNICAL_GATES_PASSED_PENDING_REVIEWER_APPROVAL``: production approval is a
human reviewer's decision recorded outside this code.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from apps.api.accessproof_api import gateway_presence
from apps.api.accessproof_api.db import (
    AIApplication, GuardAuditEvent, GuardIdentityMapping, GuardPolicy, GuardRegistration,
    ProviderSyncCursor, SourceConnection, SourceEffectiveCertification, set_tenant_context,
)
from apps.api.accessproof_api.db_security import audit as db_audit
from packages.crypto.source_certificate import REQUIRED_CHECKS, evidence_digest

PASS, FAIL, BLOCKED = "PASS", "FAIL", "BLOCKED"


def _gate(checks: dict[str, tuple[str, str]]) -> dict[str, Any]:
    states = {state for state, _ in checks.values()}
    status = FAIL if FAIL in states else BLOCKED if BLOCKED in states else PASS
    return {"status": status, "checks": {k: {"status": s, "evidence": e} for k, (s, e) in checks.items()}}


def _utc(value: datetime | None) -> datetime | None:
    return value.replace(tzinfo=timezone.utc) if value is not None and value.tzinfo is None else value


def _database_gate(db: Session) -> dict[str, Any]:
    facts_db = db_audit(db.connection())
    return _gate({
        "runtime_role_not_superuser": (PASS, facts_db["current_user"]) if not facts_db["superuser"] else (FAIL, f"{facts_db['current_user']} is SUPERUSER"),
        "runtime_role_no_bypassrls": (PASS, "NOBYPASSRLS") if not facts_db["bypassrls"] else (FAIL, "BYPASSRLS"),
        "runtime_role_owns_no_tables": (PASS, "not owner") if not facts_db["owns_tables"] else (FAIL, "owns tables"),
        "every_tenant_table_policied": (PASS, f"{facts_db['tenant_tables_checked']} tables") if not facts_db["tables_missing_policy"]
        else (FAIL, ", ".join(facts_db["tables_missing_policy"])),
        "no_settable_bypass": (PASS, "none") if not facts_db["settable_bypass_policies"] else (FAIL, f"{facts_db['settable_bypass_policies']} policies"),
        "metrics_read_only_role_configured": (PASS, "configured") if os.getenv("ACCESSPROOF_METRICS_DATABASE_URL") else (FAIL, "not configured"),
    })


def evaluate(db: Session, *, organization_id: str, application_id: str,
             host_facts: dict[str, Any] | None = None, evidence_path: Path | None = None,
             evidence: dict[str, Any] | None = None, now: datetime | None = None, window: timedelta = timedelta(days=7)) -> dict[str, Any]:
    from apps.api.accessproof_api.app import _automatic_activation_checklist, _guard_health_state, _secret_box
    from apps.api.accessproof_api.route_certification import describe_route_certificate
    from apps.api.accessproof_api.source_certification import effective_source_certified

    now = now or datetime.now(timezone.utc)
    set_tenant_context(db, organization_id)
    gates: dict[str, Any] = {}
    row = db.scalar(select(AIApplication).where(
        AIApplication.organization_id == organization_id, AIApplication.application_id == application_id,
        AIApplication.archived_at.is_(None)))
    source = db.get(SourceConnection, row.source_id) if row and row.source_id else None
    guard = db.get(GuardRegistration, row.guard_id) if row and row.guard_id else None

    # A — infrastructure (host facts are collected outside the API container)
    facts = host_facts or {}
    gates["A_INFRASTRUCTURE"] = _gate({
        name: ((PASS, "healthy") if facts.get(name) is True else
               (BLOCKED, "not collected") if name not in facts else (FAIL, str(facts.get(name))))
        for name in ("api_healthy", "worker_running", "db_healthy", "redis_healthy", "web_healthy",
                     "migration_at_head", "rollback_available")
    })

    # B — identity: verified, immutable source mappings exist for real employees
    mappings = list(db.scalars(select(GuardIdentityMapping).where(
        GuardIdentityMapping.organization_id == organization_id,
        GuardIdentityMapping.source_id == (source.id if source else ""),
        GuardIdentityMapping.status == "VERIFIED", GuardIdentityMapping.revoked_at.is_(None))))
    gates["B_IDENTITY"] = _gate({
        "two_or_more_verified_employee_mappings":
            (PASS, f"{len(mappings)} verified") if len(mappings) >= 2 else (FAIL, f"{len(mappings)} verified mappings"),
        "mappings_bound_to_entra_tenant":
            (PASS, "tenant-bound") if mappings and all(m.oidc_tenant_id for m in mappings)
            else (FAIL, "missing tenant binding"),
    })

    # C — SharePoint source, independent certificate and its evidence
    c: dict[str, tuple[str, str]] = {}
    if source is None:
        c["source_bound"] = (FAIL, "application has no source")
    else:
        c["source_connected"] = (PASS, source.status) if source.status == "connected" and not source.last_error \
            else (FAIL, f"{source.status} {source.last_error or ''}".strip())
        c["sharepoint_provider"] = (PASS, source.provider) if source.provider.lower() in {"sharepoint", "microsoft365"} \
            else (FAIL, f"provider {source.provider} is not the certified scope")
        for kind, limit in (("acl", 900), ("directory", 2400)):
            cursor = db.scalar(select(ProviderSyncCursor).where(
                ProviderSyncCursor.organization_id == organization_id, ProviderSyncCursor.source_id == source.id,
                ProviderSyncCursor.sync_kind == kind))
            seen = _utc(cursor.last_success_at) if cursor else None
            age = (now - seen).total_seconds() if seen else None
            c[f"{kind}_sync_fresh"] = (PASS, f"{int(age)}s") if age is not None and age <= limit and not cursor.last_error_code \
                else (FAIL, "stale or never synchronized")
        try:
            credentials = json.loads(_secret_box.decrypt(source.encrypted_credentials or ""))
        except Exception:
            credentials = {}
        certified = effective_source_certified(db, source, credentials)
        c["independent_certificate_valid"] = (PASS, "Ed25519 verified") if certified else \
            (FAIL, "no valid independently issued certificate for this exact scope")
        cert = db.scalar(select(SourceEffectiveCertification).where(
            SourceEffectiveCertification.organization_id == organization_id,
            SourceEffectiveCertification.source_id == source.id))
        if evidence is None and evidence_path is not None and evidence_path.is_file():
            evidence = json.loads(evidence_path.read_text())
        if cert is None or not isinstance(evidence, dict):
            c["certificate_evidence_matches"] = (BLOCKED, "evidence not supplied")
        else:
            checks = {item.get("code"): item.get("status") for item in evidence.get("checks", [])}
            missing = [code for code in REQUIRED_CHECKS if checks.get(code) != "PASS"]
            if evidence_digest(evidence) != cert.evidence_digest:
                c["certificate_evidence_matches"] = (FAIL, "evidence digest differs from certificate")
            elif missing:
                c["certificate_evidence_matches"] = (FAIL, "not PASS: " + ", ".join(missing))
            else:
                c["certificate_evidence_matches"] = (PASS, "digest matches; all required checks PASS")
    gates["C_SHAREPOINT_SOURCE"] = _gate(c)

    # D — Guard
    latest_policy = db.scalar(select(func.max(GuardPolicy.version)).where(
        GuardPolicy.organization_id == organization_id)) or 0
    d: dict[str, tuple[str, str]] = {}
    if guard is None:
        d["guard_bound"] = (FAIL, "no Guard bound")
    else:
        health = _guard_health_state(guard, now)
        d["guard_online"] = (PASS, health) if health == "online" else (FAIL, health)
        d["guard_security_ready"] = (PASS, guard.health) if guard.health == "healthy" else (FAIL, guard.health or "unknown")
        d["policy_current"] = (PASS, f"v{guard.active_policy_version}") if latest_policy and \
            guard.active_policy_version == latest_policy else (FAIL, f"guard v{guard.active_policy_version} / latest v{latest_policy}")
    gates["D_GUARD"] = _gate(d)

    # E — Gateway
    e: dict[str, tuple[str, str]] = {}
    if row is None:
        e["application_registered"] = (FAIL, "application not found")
    else:
        live = gateway_presence.connectivity(db, row, now)
        e["gateway_connected"] = (PASS, "authenticated heartbeat") if live["connection"] == "CONNECTED" else (FAIL, live["connection"])
        e["gateway_enforcement_ready"] = (PASS, "ready") if live["enforcement_ready_reported"] else (FAIL, str(live["reason"]))
        route = describe_route_certificate(db, row, now=now)
        e["route_certified"] = (PASS, route["status"]) if route.get("certified") else (FAIL, str(route.get("status")))
    gates["E_GATEWAY"] = _gate(e)

    # F/G — Layer 1 and Layer 2 observed on real traffic (Guard audit)
    def observed(layer: str, result: str) -> int:
        return int(db.scalar(select(func.count(GuardAuditEvent.id)).where(
            GuardAuditEvent.organization_id == organization_id, GuardAuditEvent.application_id == application_id,
            GuardAuditEvent.layer == layer, GuardAuditEvent.result == result,
            GuardAuditEvent.created_at >= now - window)) or 0)
    l1_allow, l1_block, l2_allow = observed("layer1", "allow"), observed("layer1", "block"), observed("layer2", "allow")
    gates["F_LAYER1"] = _gate({
        "authorized_retrieval_allowed": (PASS, f"{l1_allow} allows") if l1_allow else (FAIL, "no Layer 1 allow observed"),
        "unauthorized_retrieval_denied": (PASS, f"{l1_block} denials") if l1_block else (FAIL, "no Layer 1 denial observed"),
    })
    certified_evidence = gates["C_SHAREPOINT_SOURCE"]["checks"].get(
        "certificate_evidence_matches", {}).get("status") == PASS
    gates["G_LAYER2"] = _gate({
        "release_verified": (PASS, f"{l2_allow} verified releases") if l2_allow else (FAIL, "no Layer 2 release observed"),
        "in_flight_and_tamper_evidence": (PASS, "in certified evidence") if certified_evidence
        else (BLOCKED, "requires certified evidence"),
    })
    # H — revocation and cache: provider-observed, carried by certified evidence
    gates["H_REVOCATION_AND_CACHE"] = _gate({
        name: (PASS, "in certified evidence") if certified_evidence else (BLOCKED, "requires certified evidence")
        for name in ("revocation_observed", "stable_denial", "cache_bypass_rejected", "restoration_verified")
    })

    # I — database security, measured as the live runtime connection
    if db.connection().dialect.name != "postgresql":
        gates["I_DATABASE_SECURITY"] = _gate({"postgresql_runtime": (BLOCKED, "not PostgreSQL; cannot attest roles/RLS")})
    else:
        gates["I_DATABASE_SECURITY"] = _database_gate(db)

    # J — backend activation checklist (the same code that gates Protect)
    if row is None:
        gates["J_ACTIVATION"] = _gate({"application_registered": (FAIL, "application not found")})
    else:
        failed = [c["code"] for c in _automatic_activation_checklist(db, row) if not c["ok"]]
        gates["J_ACTIVATION"] = _gate({
            "activation_checklist": (PASS, "all checks pass") if not failed else (FAIL, ", ".join(failed)),
            "protect_acknowledged_by_guard": (PASS, "protect") if row.mode == "protect" and not failed else (FAIL, row.mode),
        })

    failing = sorted(k for k, g in gates.items() if g["status"] != PASS)
    return {
        "schema": "accessproof.production_gates/v1",
        "evaluated_at": now.isoformat(), "organization_id": organization_id, "application_id": application_id,
        "gates": gates, "failing_gates": failing,
        "verdict": "TECHNICAL_GATES_PASSED_PENDING_REVIEWER_APPROVAL" if not failing
        else "SHAREPOINT PRODUCTION PROTECT — NOT VERIFIED",
    }
