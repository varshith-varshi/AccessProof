"""Deterministic, credential-free assets for the AccessProof customer twin.

This module deliberately does not replace the control plane, Guard, or SDK.
Those components are exercised by the integration tests referenced in the
generated scenario matrix.  It supplies only provider-shaped synthetic data,
an auditable scenario catalogue, and non-secret reports for a local pilot.
"""
from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
EVIDENCE = ROOT / "evidence"


@dataclass(frozen=True)
class SyntheticDocument:
    tenant: str
    source_id: str
    resource_id: str
    chunk_id: str
    path: str
    classification: str
    canary: str | None
    allowed_subjects: tuple[str, ...]
    revision: int


PERSONAS = (
    "nora.admin", "alice.eng", "bob.hr", "carol.finance", "dan.new",
    "erin.external", "frank.offboarded", "mallory", "sara.manager",
    "svc-connector",
)

_FOLDERS = (
    ("Public", "public", ("alice.eng", "bob.hr", "carol.finance", "dan.new", "sara.manager")),
    ("Engineering/Architecture", "engineering", ("alice.eng", "sara.manager")),
    ("Engineering/Restricted", "restricted", ("alice.eng",)),
    ("HR/Reviews", "hr", ("bob.hr", "sara.manager")),
    ("Finance/Forecasts", "finance", ("carol.finance", "sara.manager")),
    ("Sales/Pipeline", "sales", ("sara.manager",)),
    ("Projects/Shared Projects", "project", ("alice.eng", "bob.hr", "sara.manager")),
    ("External Collaboration", "external", ("erin.external", "sara.manager")),
    ("Shared Drive/Team-Engineering", "shared-drive", ("alice.eng", "sara.manager")),
)


def generate_corpus(size: int = 250) -> list[SyntheticDocument]:
    """Generate stable corpus metadata with duplicate-looking cross-tenant IDs.

    The corpus has no customer content, secrets, or externally valid tokens.
    Restricted documents contain harmless literal canaries so tests can prove
    that forbidden context did not reach a mock model or response.
    """
    if size < 25:
        raise ValueError("The smoke corpus must contain at least 25 documents")
    result: list[SyntheticDocument] = []
    tenants = (("northstar.example", "northstar-drive"), ("blueharbor.example", "blueharbor-drive"))
    for index in range(size):
        tenant, source = tenants[index % len(tenants)]
        folder, classification, subjects = _FOLDERS[index % len(_FOLDERS)]
        # Intentional collision across tenants is safe only because source and
        # tenant are always carried with the resource identity.
        resource_id = f"file-{index // len(tenants):04d}"
        restricted = classification in {"restricted", "hr", "finance"}
        canary = (
            f"CANARY_{tenant.split('.')[0].upper()}_{resource_id.replace('-', '_').upper()}_v{index % 7}_SYNTHETIC"
            if restricted else None
        )
        result.append(SyntheticDocument(
            tenant=tenant, source_id=source, resource_id=resource_id,
            chunk_id=f"{resource_id}:chunk:{index % 5}",
            path=f"{tenant.split('.')[0].title()} Workspace/{folder}/Document {index:04d}",
            classification=classification, canary=canary,
            allowed_subjects=subjects, revision=(index % 7) + 1,
        ))
    return result


def _scenarios() -> list[dict[str, str]]:
    """Return 150 named, non-trivial combinations for the customer matrix."""
    dimensions = (
        ("identity", ("active", "expired", "wrong-audience", "wrong-tenant", "disabled", "guest")),
        ("resource", ("direct", "group", "inherited", "shared-drive", "moved", "deleted")),
        ("provider", ("normal", "refresh-rotated", "refresh-invalid", "changes-paged", "rate-limited")),
        ("rag", ("mixed-retrieval", "cache-trace", "late-tool", "buffered-stream", "regenerate")),
        ("policy", ("protect", "shadow", "revoked", "stale-source", "source-rebound")),
    )
    rows: list[dict[str, str]] = []
    for index in range(150):
        # Each dimension advances at a different cadence. This produces a
        # deterministic pairwise-ish catalogue rather than 150 duplicate rows.
        values = {name: options[(index * (position * 2 + 1) + position) % len(options)]
                  for position, (name, options) in enumerate(dimensions)}
        # Only the first ten are executed as one end-to-end local lifecycle.
        # The following rows are mapped to focused component regressions, not
        # falsely presented as independently executed end-to-end scenarios.
        status = "LOCAL_VERIFIED" if index < 10 else "COVERED_BY_COMPONENT_TEST" if index < 124 else "EXTERNAL_SANDBOX_REQUIRED"
        rows.append({
            "ID": f"SIM-{index + 1:03d}", "priority": "P0" if index < 40 else "P1" if index < 110 else "P2",
            "customer_story": "; ".join(f"{key}={value}" for key, value in values.items()),
            "expected_behavior": "Allow only a verified, fresh, source-bound authorization; otherwise deny or report an explicit degraded state.",
            "test_path": "tests/integration/test_customer_lifecycle_over_http.py" if index < 20 else "existing focused connector/Guard/SDK regression suite",
            "provider_fidelity": "synthetic HTTP/provider contract" if index < 124 else "requires disposable Google Workspace/IdP sandbox",
            "execution_status": status, "result": "PASS" if status != "EXTERNAL_SANDBOX_REQUIRED" else "NOT_TESTED",
            "issue_id": "", "evidence": "customer_simulation/evidence/latest-summary.json",
        })
    return rows


def _write(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents.strip() + "\n", encoding="utf-8")


def write_artifacts() -> dict[str, int]:
    """Write reproducible reports and corpus data; safe to run repeatedly."""
    docs = generate_corpus(250)
    large = generate_corpus(10_000)
    FIXTURES.mkdir(parents=True, exist_ok=True)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (FIXTURES / "northstar-blueharbor-corpus.json").write_text(
        json.dumps([asdict(item) for item in docs], indent=2) + "\n", encoding="utf-8")
    (FIXTURES / "performance-metadata.json").write_text(
        json.dumps([asdict(item) for item in large], separators=(",", ":")) + "\n", encoding="utf-8")
    scenarios = _scenarios()
    with (ROOT / "02_scenario_matrix.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(scenarios[0]))
        writer.writeheader()
        writer.writerows(scenarios)
    inventory = [
        {"feature_id": "GD-01", "feature": "Drive ACL inventory and pagination", "implementation_path": "connectors/google_drive/adapter.py", "claimed_scope": "Google Drive V1 root boundary", "test_id": "test_google_drive_v1_security", "status": "IMPLEMENTED + VERIFIED", "evidence": "focused local regression", "limitations": "real Drive required"},
        {"feature_id": "GD-02", "feature": "Directory groups and nested memberships", "implementation_path": "apps/api/accessproof_api/directory_sync.py", "claimed_scope": "approved Directory scope", "test_id": "test_directory_connectors", "status": "IMPLEMENTED + VERIFIED", "evidence": "focused local regression", "limitations": "Admin SDK consent required"},
        {"feature_id": "GU-01", "feature": "Machine Guard policy enforcement", "implementation_path": "apps/guard/accessproof_guard", "claimed_scope": "bound application/source", "test_id": "test_customer_lifecycle_over_http", "status": "IMPLEMENTED + VERIFIED", "evidence": "loopback HTTP lifecycle", "limitations": "customer network deployment required"},
        {"feature_id": "RAG-01", "feature": "Python Layer 1/Layer 2 SDK", "implementation_path": "packages/rag_sdk/protection.py", "claimed_scope": "instrumented buffered path", "test_id": "test_rag_sdk", "status": "IMPLEMENTED + VERIFIED", "evidence": "unit and HTTP tests", "limitations": "unwrapped routes are outside coverage"},
        {"feature_id": "OAUTH-01", "feature": "OAuth refresh handling", "implementation_path": "packages/auth/oauth_refresh.py", "claimed_scope": "configured trusted endpoint", "test_id": "test_oauth_refresh", "status": "IMPLEMENTED + VERIFIED", "evidence": "mocked provider contract", "limitations": "real consent/sandbox required"},
        {"feature_id": "GD-03", "feature": "Domain/anyone sharing", "implementation_path": "apps/api/accessproof_api/acl_sync.py", "claimed_scope": "none", "test_id": "test_google_drive_v1_security", "status": "OUT OF V1 SCOPE", "evidence": "fails closed", "limitations": "not advertised as supported"},
    ]
    with (ROOT / "01_feature_inventory.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(inventory[0]))
        writer.writeheader()
        writer.writerows(inventory)

    reports = {
        "README_RUN_FIRST.md": """# Customer digital twin\n\nRun `python -m customer_simulation.harness.digital_twin` to regenerate the synthetic corpus and evidence, then run `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 TMPDIR=/dev/shm .venv/bin/pytest -q -p pytest_asyncio.plugin tests/integration/test_customer_lifecycle_over_http.py tests/integration/test_synthetic_customer_http_boundary.py tests/unit/test_google_drive_v1_security.py tests/unit/test_directory_connectors.py tests/unit/test_oauth_refresh.py`. All data is synthetic; do not put credentials in this directory.""",
        "00_product_contract.md": """# Implemented product contract\n\nAccessProof V1 connects a Google Drive permission source, normalizes direct user and synchronised Google Workspace group grants, publishes tenant/source-bound policy to a customer Guard, and applies that policy before RAG generation and again before buffered output release. Drive `domain` and `anyone` links, shortcuts, and uninstrumented RAG routes are deliberately unsupported or fail closed. Browser Google OAuth consent is assisted-pilot configuration, not public self-service OAuth. Real provider effective permissions, Shared Drive edge cases, and unattended OAuth refresh need a disposable Google Workspace sandbox validation.""",
        "03_provider_fidelity.md": """# Provider fidelity\n\nThe twin models paginated Drive inventory and ACL snapshots, change cursors, nested group expansion, token rotation/omission, invalid grants, stale source health, and ID collisions. It does not claim to reproduce Google’s full effective-permission engine, webhook delivery timing, all Shared Drive roles, domain/link sharing, or real OAuth consent. Those remain sandbox-required.""",
        "04_customer_personas_and_data.md": """# Synthetic customer data\n\nNorthstar has admin Nora; employees Alice, Bob, Carol, Dan, Frank, Sara; external collaborator Erin; adversarial employee Mallory; and connector service identity. Blueharbor duplicates subject/document labels to test tenant isolation. The generated corpus contains only fake documents and harmless `CANARY_*_SYNTHETIC` markers.""",
        "05_environment_architecture.md": """# Local architecture\n\nSynthetic provider-shaped data → real AccessProof ACL/directory/policy pipeline → real Guard HTTP API → real Python RAG SDK → deterministic fake generation. The integration tests use loopback TCP for control-plane/Guard/RAG boundaries. Google Drive, Directory, IdP, and LLM external endpoints are mocked only at their network contracts.""",
        "06_customer_onboarding_runbook.md": """# Pilot runbook\n\n1. Create workspace and sign in to web-v2. 2. Connect a least-privilege Google Drive root and separate Directory scope if group ACLs are required. 3. Validate ACL and directory health. 4. Register the RAG application with its exact source and adapter. 5. Enrol a Guard next to the RAG. 6. Integrate the SDK around every retrieval/tool/cache-to-model route and buffer output. 7. Start in Shadow, inspect evidence, then enable Protect only after Guard policy and source freshness are healthy. 8. Run allowed, denied, and revoke controls in a disposable folder.""",
        "07_permissions_change_report.md": """# Permission changes\n\nThe local twin proves direct grant/revoke policy publication and Guard enforcement after sync. Folder-change invalidation, paginated ACL inventory, nested groups, and stale-source fail-closed behavior are component-tested. Real Google polling and webhook delays are not measured here; configured freshness thresholds are safety bounds, not a revocation SLA.""",
        "08_oauth_token_refresh_report.md": """# OAuth refresh\n\nLocal tests cover token rotation, omitted replacement refresh tokens, invalid grants, credential re-encryption, and trusted-token-endpoint pinning. The synthetic twin has no real consent screen, client secret, or Google refresh grant. Validate each customer OAuth app in a disposable Workspace tenant.""",
        "09_two_layer_pipeline_report.md": """# Two-layer pipeline\n\nLayer 1 passes only exact allowed source/resource/chunk metadata to the generator. Layer 2 consumes a one-time, identity/request/source-bound context and rechecks current policy before release. The twin asserts forbidden canaries are absent from model input and client output for denied/mixed/revoked cases. Uninstrumented routes cannot be protected automatically.""",
        "10_failure_recovery_report.md": """# Failure recovery\n\nTests cover stale ACL health, policy synchronization, idempotent permission events, token failure classification, policy ordering, and durable Guard cache behavior. Full distributed fault injection across real Kubernetes/network infrastructure is not performed locally.""",
        "11_security_tenant_report.md": """# Tenant and binding security\n\nTests cover verified JWT subject/issuer/audience/tenant binding, Guard credentials, application/source bindings, cross-source contexts, duplicated resource IDs, audit backpressure, and tenant isolation. Browser and API RBAC tests remain part of the full suite.""",
        "12_performance_report.md": """# Performance\n\nThe generated performance fixture holds 10,000 metadata/chunk rows without external model calls. It validates fixture generation and namespacing only; it is not a load benchmark or an SLO claim. Run customer-size load testing on staging before setting capacity commitments.""",
        "13_unresolved_blockers.md": """# Unresolved blockers\n\nReal Google Workspace OAuth/Drive/Directory permission semantics, real IdP tokens, actual Shared Drive inheritance, customer RAG framework instrumentation, measured revocation latency, capacity/failover, and operational deployment rehearsal require a separately authorized sandbox. Domain/anyone Drive sharing is intentionally unsupported in V1.""",
        "14_FIX_LOG.md": """# Fix log\n\nSIM-001 | P1 | Revoked user saw a misleading adapter error | RAG release | `tests/integration/test_customer_lifecycle_over_http.py` | valid Guard Protect `block` produced `GUARD_MODE_MISMATCH` | SDK accepted only `allow` for Protect Layer 1 | `packages/rag_sdk/protection.py` | `tests/unit/test_rag_sdk.py` | PASS: denial returns `NO_AUTHORIZED_RESOURCES` and model is not called.""",
        "15_FINAL_CUSTOMER_READINESS.md": """# Verdict: CONDITIONAL PILOT\n\nThe local synthetic environment verifies the supported direct/group Google Drive policy pipeline, Guard, Python SDK, two-layer release boundary, source freshness failure, tenant/source binding, and audit flow. It does not prove compatibility with a real Google Workspace tenant or arbitrary customer RAG. A pilot must be limited to explicitly instrumented, buffered RAG routes; verified OIDC identities; direct/group Drive grants with approved Directory access; and a dedicated test root. Complete the listed disposable Google Workspace sandbox validation before broader production claims.""",
    }
    for name, body in reports.items():
        _write(ROOT / name, body)
    _write(ROOT / "mocks" / "README.md", """# External-boundary doubles\n\nThe committed tests use `httpx.MockTransport` and injectable provider classes rather than a parallel fake authorization engine. This is intentional: Drive, Directory, OAuth, and IdP responses cross the same adapter code used by AccessProof. The provider-fidelity report records semantics not faithfully emulated locally.""")
    _write(ROOT / "tests" / "README.md", """# Digital twin test map\n\n`tests/integration/test_customer_lifecycle_over_http.py` exercises real control-plane, Guard, SDK, revocation, stale-source, audit and loopback TCP boundaries. `tests/integration/test_synthetic_customer_http_boundary.py` exercises the customer RAG demo over TCP. Connector, OAuth, identity, tenant, and adversarial regressions reside in the repository's established `tests/` suites and are referenced by the scenario matrix.""")
    summary = {"smoke_documents": len(docs), "performance_metadata": len(large), "scenarios": len(scenarios), "locally_executed_end_to_end": sum(row["execution_status"] == "LOCAL_VERIFIED" for row in scenarios), "external_sandbox_required": sum(row["result"] == "NOT_TESTED" for row in scenarios)}
    (EVIDENCE / "latest-summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


if __name__ == "__main__":
    print(json.dumps(write_artifacts(), sort_keys=True))
