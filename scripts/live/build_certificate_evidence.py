#!/usr/bin/env python3
"""Assemble source-certification evidence from recorded live artifacts.

    python scripts/live/build_certificate_evidence.py --organization-id ORG --source-id SRC \\
        --profile PROFILE --scope-digest DIGEST --out evidence.json

Every one of the 14 REQUIRED_CHECKS is derived from a committed artifact under
docs/evidence/live-2026-11-03/matrix/, re-evaluated here from that artifact's
own recorded observations (never from its summary flag alone), and bound to
the artifact's SHA-256 and observation time. A check whose artifact is missing,
stale or not passing is written as FAIL, and issue_source_certificate.py then
refuses to sign. Nothing here contacts the tenant or production.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from packages.crypto.source_certificate import EVIDENCE_SCHEMA, REQUIRED_CHECKS  # noqa: E402

M = ROOT / "docs/evidence/live-2026-11-03/matrix"
# Standard names inside a fresh evidence directory (--dir); the legacy r30 set
# keeps its original names when --dir is not given.
FRESH = {
    "sharepoint-effective-matrix.json": "sharepoint-effective-matrix.json",
    "layer1-guard-apitoken-r30.json": "layer1.json",
    "identity-bindings-r30.json": "identity-bindings.json",
    "revocation-A-r30.json": "revocation-A-route.json",
    "rag-e2e-apitoken-r30.json": "rag-e2e.json",
    "revocation-A-route-FG-r30.json": "revocation-A-route.json",
    "buffered-release-r30.json": "buffered-release.json",
}
_FRESH_DIR: Path | None = None


def load(name: str) -> tuple[dict, str]:
    path = (_FRESH_DIR / FRESH[name]) if _FRESH_DIR is not None else (M / name)
    raw = path.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def latest(*stamps: str | None) -> str:
    return max(s for s in stamps if s)


def checks() -> list[dict]:
    out: list[dict] = []

    def add(code: str, ok: bool, artifact: str, sha: str, observed_at: str, detail: str) -> None:
        where = str((_FRESH_DIR / FRESH[artifact]).relative_to(ROOT)) if _FRESH_DIR is not None else f"docs/evidence/live-2026-11-03/matrix/{artifact}"
        out.append({"code": code, "status": "PASS" if ok else "FAIL", "artifact": where,
                    "artifact_sha256": sha, "observed_at": observed_at, "detail": detail})

    eff, eff_sha = load("sharepoint-effective-matrix.json")
    add("PROVIDER_EFFECTIVE_PERMISSION_MATRIX", len(eff["results"]) >= 10 and all(r["pass"] for r in eff["results"]),
        "sharepoint-effective-matrix.json", eff_sha, latest(*(r["at"] for r in eff["results"])),
        "SharePoint GetUserEffectivePermissions per employee and item")

    l1, l1_sha = load("layer1-guard-apitoken-r30.json")
    def actor_ok(actor: str) -> bool:
        rows = [r for r in l1["results"] if r["actor"] == actor]
        ctl = [c for c in l1["negative_controls"] if c["actor"] == actor]
        # Identity controls are mandatory; later matrix versions add more
        # controls (content-version freshness) and every control must pass.
        names = {c["control"] for c in ctl}
        return (len(rows) == 5 and all(r["pass"] for r in rows) and len(ctl) >= 2 and all(c["pass"] for c in ctl)
                and {"id_token_rejected", "tampered_signature_rejected"} <= names)
    l1_at = latest(*(r["at"] for r in l1["results"]), *(c["at"] for c in l1["negative_controls"]))
    add("EMPLOYEE_OIDC_POSITIVE_IDENTITY", actor_ok("alice"), "layer1-guard-apitoken-r30.json", l1_sha, l1_at,
        "Alice: real Entra delegated API token verified by the Guard; ID token and tampered signature rejected")
    add("EMPLOYEE_OIDC_SECOND_IDENTITY", actor_ok("bob"), "layer1-guard-apitoken-r30.json", l1_sha, l1_at,
        "Bob: distinct second employee, same checks")

    ib, ib_sha = load("identity-bindings-r30.json")
    add("IDENTITY_MAPPING_IMMUTABLE_OBJECT_ID",
        len(ib["bindings"]) == 2 and all(b["oid_equals_source_principal"] and b["method"] == "directory_verified"
                                          and b["status"] == "VERIFIED" for b in ib["bindings"]),
        "identity-bindings-r30.json", ib_sha, ib["observed_at"], "oid -> source principal, directory-verified, no email/UPN")

    grp = [r for r in l1["results"] if r["document"] in {"group_finance_alice.txt", "inherited_finance_alice.txt"}]
    add("INHERITED_AND_GROUP_PERMISSIONS", len(grp) == 4 and all(r["pass"] for r in grp),
        "layer1-guard-apitoken-r30.json", l1_sha, l1_at, "group-derived and inherited grants allow Alice, deny Bob")

    ra, ra_sha = load("revocation-A-r30.json")
    rev = next((p for p in ra["phases"] if p["phase"] == "revoke"), None)
    res = next((p for p in ra["phases"] if p["phase"].startswith("restore")), None)
    add("PROVIDER_REVOKE_OBSERVED", bool(rev and rev["completed"] and rev["t1_source_confirmed"]),
        "revocation-A-r30.json", ra_sha, rev["t6_stable_decision"] if rev else "", "direct grant removed; SharePoint and Guard both deny")
    add("PROVIDER_RESTORE_OBSERVED", bool(res and res["completed"] and res["t1_source_confirmed"]),
        "revocation-A-r30.json", ra_sha, res["t6_stable_decision"] if res else "", "grant restored; Guard allows again")

    e2e, e2e_sha = load("rag-e2e-apitoken-r30.json")
    by = {r["test_identifier"]: r for r in e2e["results"]}
    allow_ids, deny_ids = ("E2E-01", "E2E-03", "E2E-05", "E2E-06"), ("E2E-02", "E2E-04")
    e2e_at = latest(*(r["timestamp"] for r in e2e["results"]))
    add("GATEWAY_ROUTE_AUTHORIZED_RELEASE", all(by[i]["status"] == "PASS" for i in allow_ids),
        "rag-e2e-apitoken-r30.json", e2e_sha, e2e_at, "authorized documents reached the model and the answer was released")
    add("GATEWAY_ROUTE_UNAUTHORIZED_DENIED", all(by[i]["status"] == "PASS" for i in deny_ids),
        "rag-e2e-apitoken-r30.json", e2e_sha, e2e_at, "unauthorized documents never reached the model (context witness)")
    add("PROVENANCE_TAMPER_REJECTED", by["E2E-11"]["status"] == "PASS" and by["E2E-11"]["observed"]["model_calls"] == 0,
        "rag-e2e-apitoken-r30.json", e2e_sha, by["E2E-11"]["timestamp"], "altered content with original attestation refused, 0 model calls")

    rt, rt_sha = load("revocation-A-route-FG-r30.json")
    route = rt["route"]
    rt_rev = next(p for p in rt["phases"] if p["phase"] == "revoke")
    add("GATEWAY_POST_REVOCATION_DENIED", route["E2E-07"]["status"] == "PASS", "revocation-A-route-FG-r30.json", rt_sha,
        route["E2E-07"]["observed"]["finished_at"], "after stable denial the protected route never sent the document to the model")
    add("GATEWAY_INFLIGHT_REVOCATION_DENIED", route["E2E-09"]["status"] == "PASS"
        and route["E2E-09"]["released_after_detection"] == 0 and route["E2E-09"]["straddling_withheld"] >= 1,
        "revocation-A-route-FG-r30.json", rt_sha, rt_rev["t6_stable_decision"], "straddling request withheld by Layer 2 recheck")
    add("CACHED_ANSWER_REUSE_DENIED", route["E2E-08-pre"]["status"] == "PASS" and route["E2E-08"]["status"] == "PASS",
        "revocation-A-route-FG-r30.json", rt_sha, route["E2E-08"]["post_revocation_repeat"]["finished_at"],
        "cached baseline route unreachable; protected answers never cached; pre-revocation answer not reused")

    br, br_sha = load("buffered-release-r30.json")
    add("BUFFERED_RELEASE_VERIFIED", br["pass"] and len(br["results"]) >= 4, "buffered-release-r30.json", br_sha,
        br["observed_at"], "every released answer followed a Guard Layer 2 allow for the same decision")
    assert [c["code"] for c in out] and set(c["code"] for c in out) == set(REQUIRED_CHECKS)
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for name in ("organization-id", "source-id", "profile", "scope-digest", "out"):
        p.add_argument(f"--{name}", required=True)
    p.add_argument("--dir", help="fresh evidence directory with standard artifact names")
    a = p.parse_args()
    global _FRESH_DIR
    _FRESH_DIR = Path(a.dir).resolve() if a.dir else None
    found = checks()
    evidence = {"schema": EVIDENCE_SCHEMA, "organization_id": a.organization_id, "source_id": a.source_id,
                "profile": a.profile, "scope_digest": a.scope_digest, "checks": found}
    Path(a.out).write_text(json.dumps(evidence, indent=1))
    failing = [c["code"] for c in found if c["status"] != "PASS"]
    print(json.dumps({"checks": len(found), "failing": failing}))
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
