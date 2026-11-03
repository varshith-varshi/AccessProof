#!/usr/bin/env python3
"""Build the 2026-11-03 security-assessment package from real artifacts.

Inputs: docs/security-assessment-2026-11-03/findings.json and pytest JUnit XML
for the SQLite and PostgreSQL runs. Nothing is hand-entered: every local result
comes from a JUnit test case, and every live (tenant/production) result that was
not observed is emitted as BLOCKED with null actual/evidence fields.

  python scripts/build_security_assessment.py --sqlite-junit a.xml --pg-junit b.xml
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/security-assessment-2026-11-03"
TENANT_REF = "6479e7ca-b256-4ebc-a408-871b9046547c (reference; not re-verified)"
APP_REF = "sharepoint-rag (reference)"
SOURCE_REF = "neuralmatrix093.sharepoint.com / drive 8200ffae-ba10-42c5-bfa9-8f7ac155c5c4 (reference; not re-verified)"
BLOCK_REASON = ("No live Microsoft/production access from this session: graph.microsoft.com and "
                "api/app.accessproof.in denied by network policy; AWS STS InvalidClientTokenId.")


def junit_cases(path: Path) -> dict[str, dict[str, str]]:
    root = ET.parse(path).getroot()
    out: dict[str, dict[str, str]] = {}
    for case in root.iter("testcase"):
        name = f"{case.get('classname')}::{case.get('name')}"
        status = ("failed" if case.find("failure") is not None or case.find("error") is not None
                  else "skipped" if case.find("skipped") is not None else "passed")
        out[name] = {"status": status, "time": case.get("time") or "0"}
    return out


def local_record(test_id: str, cases: dict[str, dict[str, str]], needle: str, *, expected: str, document: str,
                 employee: str) -> dict:
    hits = {k: v for k, v in cases.items() if needle in k}
    statuses = collections.Counter(v["status"] for v in hits.values())
    status = ("NOT_FOUND" if not hits else "FAIL" if statuses["failed"] else
              "PASS_LOCAL" if statuses["passed"] else "SKIPPED")
    digest = hashlib.sha256(json.dumps(sorted(hits.items())).encode()).hexdigest() if hits else None
    return {"test_identifier": test_id, "environment": "local-synthetic", "organization": "synthetic",
            "application": "synthetic", "source": "synthetic SharePoint replica",
            "employee_identity_reference": employee, "document_reference": document,
            "expected_decision": expected, "actual_decision": expected if status == "PASS_LOCAL" else None,
            "authorization_revision": "synthetic", "observed_behavior": f"{dict(statuses)} across {len(hits)} test cases matching '{needle}'",
            "evidence_hash": digest, "status": status}


def live_record(test_id: str, *, expected: str, document: str, employee: str, evidence_required: str) -> dict:
    return {"test_identifier": test_id, "environment": "live-tenant", "timestamp": None,
            "organization": "production (not reached)", "application": APP_REF, "source": SOURCE_REF,
            "employee_identity_reference": employee, "document_reference": document,
            "expected_decision": expected, "actual_decision": None, "authorization_revision": None,
            "observed_behavior": None, "evidence_hash": None, "status": "BLOCKED",
            "blocked_reason": BLOCK_REASON, "evidence_required": evidence_required}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sqlite-junit", type=Path, required=True)
    ap.add_argument("--pg-junit", type=Path, required=True)
    args = ap.parse_args()
    now = datetime.now(timezone.utc).isoformat()
    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    sqlite, pg = junit_cases(args.sqlite_junit), junit_cases(args.pg_junit)
    findings = json.loads((OUT / "findings.json").read_text())

    def totals(cases):
        c = collections.Counter(v["status"] for v in cases.values())
        return {"tests": len(cases), "passed": c["passed"], "failed": c["failed"], "skipped": c["skipped"]}

    header = {"generated_at": now, "git_commit": commit, "tenant_reference": TENANT_REF,
              "live_status": "BLOCKED", "live_blocked_reason": BLOCK_REASON,
              "local_totals": {"sqlite": totals(sqlite), "postgresql_restricted_role": totals(pg)}}

    matrix = [("finance_alice.txt", "alice", "ALLOW"), ("finance_alice.txt", "bob", "DENY"),
              ("engineering_bob.txt", "bob", "ALLOW"), ("engineering_bob.txt", "alice", "DENY"),
              ("shared_control.txt", "alice", "ALLOW"), ("shared_control.txt", "bob", "ALLOW")]

    def write(name: str, body: dict) -> None:
        (OUT / name).write_text(json.dumps({**header, **body}, indent=2) + "\n")

    write("SHAREPOINT_SOURCE_VALIDATION.json", {"schema": "accessproof.sharepoint_source_validation/v1", "records": [
        live_record(f"SRC-{i:02d}", expected=e, document=d, employee="n/a", evidence_required=r) for i, (d, e, r) in enumerate([
            ("tenant/app registration", "CONFIGURED_LEAST_PRIVILEGE", "app registration export; requiredResourceAccess; admin consent"),
            ("site grant", "Sites.Selected limited to lab site", "/sites/{id}/permissions export"),
            ("site/drive discovery", "lab site and drive only", "discovery transcript; unauthorized site returns 403/404"),
            ("document indexing", "3 synthetic documents attested", "ingestion records with eTags and attestation key ids"),
        ], 1)] + [local_record("SRC-L1", sqlite, "provider_id_path_delimiters", expected="REJECT", document="crafted ids", employee="n/a"),
                  local_record("SRC-L2", sqlite, "forged_provenance", expected="BLOCK", document="forged attestation", employee="n/a")]})
    write("SHAREPOINT_IDENTITY_VALIDATION.json", {"schema": "accessproof.sharepoint_identity_validation/v1", "records": [
        live_record("ID-01", expected="VERIFIED oid mapping", document="n/a", employee="alice (Entra)", evidence_required="Guard audit with verified iss/tid/oid + VERIFIED tenant-bound mapping"),
        live_record("ID-02", expected="VERIFIED oid mapping", document="n/a", employee="bob (Entra)", evidence_required="same as ID-01 for Bob"),
        local_record("ID-L1", sqlite, "test_entra_identity_negative_matrix", expected="REJECT all forged/misbound; accept valid", document="n/a", employee="synthetic alice/bob"),
        local_record("ID-L2", sqlite, "test_microsoft_group_identity_confusion", expected="no group/user confusion", document="n/a", employee="synthetic")]})
    write("SHAREPOINT_EFFECTIVE_ACL_MATRIX.json", {"schema": "accessproof.sharepoint_effective_acl_matrix/v1",
        "source_of_truth_check": [live_record(f"ACL-SP-{i}", expected=e, document=d, employee=u, evidence_required="direct SharePoint access check as the employee") for i, (d, u, e) in enumerate(matrix, 1)],
        "through_accessproof": [live_record(f"ACL-AP-{i}", expected=e, document=d, employee=u, evidence_required="Guard Layer 1 decision against the real source") for i, (d, u, e) in enumerate(matrix, 1)],
        "local": [local_record("ACL-L1", sqlite, "test_single_requester_behaviour_is_unchanged", expected="matrix holds", document="synthetic finance/engineering/shared", employee="synthetic alice/bob"),
                  local_record("ACL-L2", sqlite, "test_sharepoint_link_and_guest_grants_fail_closed", expected="links/guests never ALLOW", document="synthetic", employee="synthetic")]})
    write("SHAREPOINT_GUARD_VALIDATION.json", {"schema": "accessproof.sharepoint_guard_validation/v1", "records": [
        live_record("GRD-01", expected="authorization-ready", document="n/a", employee="n/a", evidence_required="gate D PASS on production"),
        local_record("GRD-L1", sqlite, "guard", expected="fail closed on stale policy / wrong identity / unavailable", document="synthetic", employee="synthetic")]})
    write("SHAREPOINT_GATEWAY_VALIDATION.json", {"schema": "accessproof.sharepoint_gateway_validation/v1", "records": [
        live_record("GW-01", expected="CONNECTED + enforcement ready", document="n/a", employee="n/a", evidence_required="gate E PASS; authenticated heartbeat from the customer Gateway"),
        live_record("GW-02", expected="no direct route to model", document="n/a", employee="n/a", evidence_required="network probe on the customer host"),
        local_record("GW-L1", sqlite, "test_gateway_presence", expected="authenticated heartbeat only", document="n/a", employee="n/a")]})
    write("SHAREPOINT_LAYER1_RESULTS.json", {"schema": "accessproof.sharepoint_layer1_results/v1", "records": [
        live_record(f"L1-{i}", expected=e, document=d, employee=u, evidence_required="captured model request proving only authorized chunks") for i, (d, u, e) in enumerate(matrix, 1)] + [
        local_record("L1-L1", sqlite, "test_poisoned_authorized_document", expected="restricted chunk never reaches model", document="synthetic", employee="synthetic bob")]})
    write("SHAREPOINT_LAYER2_RESULTS.json", {"schema": "accessproof.sharepoint_layer2_results/v1", "records": [
        live_record("L2-01", expected="buffered, provenance verified, revision-bound release", document="lab documents", employee="alice/bob", evidence_required="Layer 2 audit events from live traffic"),
        local_record("L2-L1", sqlite, "test_gateway_strips_injected_exfiltration", expected="exfiltration stripped", document="synthetic", employee="synthetic")]})
    write("SHAREPOINT_REVOCATION_RESULTS.json", {"schema": "accessproof.sharepoint_revocation_results/v1",
        "latency_measured": False, "slo_claimed": None, "records": [
        live_record(f"REV-{t}", expected="DENY after propagation" if t != "E" else "ALLOW after restore", document="finance_alice.txt", employee="alice",
                    evidence_required="7 timestamps per Part 4.8 from the authorized trial") for t in "ABCDEFG"] + [
        local_record("REV-L1", sqlite, "revocation", expected="DENY", document="synthetic", employee="synthetic"),
        local_record("REV-L2", sqlite, "inflight", expected="DENY", document="synthetic", employee="synthetic"),
        local_record("REV-L3", sqlite, "mid_generation_revocation", expected="no streamed release after revocation", document="synthetic", employee="synthetic")]})
    write("SHAREPOINT_RAG_E2E_RESULTS.json", {"schema": "accessproof.sharepoint_rag_e2e_results/v1", "records": [
        live_record(f"E2E-{i:02d}", expected=e, document=d, employee=u, evidence_required="live protected RAG answer + Guard audit") for i, (u, d, e) in enumerate([
            ("alice", "finance question", "ALLOW"), ("bob", "finance question", "DENY"), ("bob", "engineering question", "ALLOW"),
            ("alice", "engineering question", "DENY"), ("alice", "shared question", "ALLOW"), ("bob", "shared question", "ALLOW"),
            ("alice", "after revocation", "DENY"), ("alice", "stale cached answer", "DENY"), ("alice", "in-flight revocation", "DENY"),
            ("alice", "Guard unavailable", "FAIL_CLOSED"), ("alice", "invalid provenance", "DENY")], 1)]})
    # Part 12 machine-readable files mirror the same records.
    for name, src in (("ACCESSPROOF_SHAREPOINT_E2E_RESULTS.json", "SHAREPOINT_RAG_E2E_RESULTS.json"),
                      ("ACCESSPROOF_REVOCATION_TEST_RESULTS.json", "SHAREPOINT_REVOCATION_RESULTS.json")):
        (OUT / name).write_text((OUT / src).read_text())
    write("ACCESSPROOF_AUTHORIZATION_TEST_RESULTS.json", {"schema": "accessproof.authorization_test_results/v1", "records": [
        local_record("AUTHZ-01", sqlite, "test_cross_tenant_route_sweep", expected="no cross-tenant access", document="all routes", employee="attacker tenant"),
        local_record("AUTHZ-02", pg, "test_cross_tenant_route_sweep", expected="no cross-tenant access (PostgreSQL, restricted role)", document="all routes", employee="attacker tenant"),
        local_record("AUTHZ-03", sqlite, "test_account_attack_matrix", expected="no escalation", document="n/a", employee="synthetic members"),
        local_record("AUTHZ-04", pg, "test_postgres_tenant_isolation", expected="RLS enforced for restricted roles", document="n/a", employee="n/a"),
        local_record("AUTHZ-05", sqlite, "test_participant_aware_authorization", expected="intersection of participants", document="synthetic", employee="synthetic")]})
    register = ["# AccessProof vulnerability register — 2026-11-03", "",
                findings["scope_note"], "",
                "Status: FIXED_LOCAL = committed and tested locally; FIXED_REHEARSAL = also exercised on the "
                "production-shaped stand-in. **Nothing here is deployed to production.**", "",
                "| ID | Sev | Title | Status | Deployed | Reproduction | Regression tests |", "|---|---|---|---|---|---|---|"]
    for f in findings["findings"]:
        register.append(f"| {f['id']} | {f['severity']} | {f['title']} | {f['status']} | {'yes' if f['deployed'] else 'no'} | "
                        f"{f['reproduction']} | {'; '.join(f['regression_tests']) or '—'} |")
    (OUT / "ACCESSPROOF_VULNERABILITY_REGISTER.md").write_text("\n".join(register) + "\n")
    matrix_md = ["# AccessProof adversarial test matrix — 2026-11-03", "",
                 "Every row ran in the isolated environment unless marked BLOCKED. Live = real tenant/production.", "",
                 "| ID | Area | Attack | Result | Evidence | Live |", "|---|---|---|---|---|---|"]
    for a in findings["attacks_that_held"]:
        matrix_md.append(f"| {a['id']} | {a['area']} | {a['attack']} | HELD — {a['result']} | `{a['test']}` | BLOCKED |")
    for f in findings["findings"]:
        matrix_md.append(f"| {f['id']} | {f['component']} | {f['reproduction']} | FOUND → {f['status']} | "
                         f"{'; '.join(f['regression_tests']) or '—'} | BLOCKED |")
    (OUT / "ACCESSPROOF_ADVERSARIAL_TEST_MATRIX.md").write_text("\n".join(matrix_md) + "\n")
    rehearsal_gates_path = ROOT / "docs/evidence/rehearsal-2026-11-03/gates-r23-least-privilege.json"
    rehearsal = json.loads(rehearsal_gates_path.read_text())
    st, pt = header["local_totals"]["sqlite"], header["local_totals"]["postgresql_restricted_role"]
    green = st["failed"] == 0 and pt["failed"] == 0 and st["tests"] > 0 and pt["tests"] > 0
    write("ACCESSPROOF_PRODUCTION_SECURITY_GATES.json", {
        "schema": "accessproof.production_security_gates/v1",
        "verdict": "SHAREPOINT PRODUCTION PROTECT — NOT VERIFIED",
        "production_gates": {g: {"status": "BLOCKED", "reason": BLOCK_REASON} for g in (
            "A_INFRASTRUCTURE", "B_IDENTITY", "C_SHAREPOINT_SOURCE", "D_GUARD", "E_GATEWAY", "F_LAYER1",
            "G_LAYER2", "H_REVOCATION_AND_CACHE", "I_DATABASE_SECURITY", "J_ACTIVATION")},
        "rehearsal_stand_in_gates": {"source": str(rehearsal_gates_path.relative_to(ROOT)),
                                     "note": "production-shaped local stand-in, NOT production; measured before this assessment's fixes",
                                     "verdict": rehearsal["verdict"],
                                     "gates": {k: v["status"] for k, v in rehearsal["gates"].items()}},
        "regression": {"sqlite": st, "postgresql_restricted_role": pt, "all_green": green},
        "reviewer_approval": "NOT RECORDED"})

    def summary(t):
        return f"{t['passed']} passed, {t['failed']} failed, {t['skipped']} skipped ({t['tests']} tests)"
    fills = {"{{COMMIT}}": commit[:12], "{{SQLITE}}": summary(st), "{{PG}}": summary(pt),
             "{{REGRESSION_STATUS}}": "PASS-LOCAL" if green else "FAIL",
             "{{UPGRADE_RESULT}}": f"SQLite {summary(st)}; PostgreSQL as accessproof_app {summary(pt)}"}
    for md in OUT.glob("*.md"):
        text = md.read_text()
        for key, value in fills.items():
            text = text.replace(key, value)
        md.write_text(text)
    leftovers = [md.name for md in OUT.glob("*.md") if "{{" in md.read_text()]
    if leftovers:
        raise SystemExit(f"unfilled placeholders in {leftovers}")
    print(json.dumps({"commit": commit, **header["local_totals"]}))


if __name__ == "__main__":
    main()
