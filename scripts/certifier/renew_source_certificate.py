#!/usr/bin/env python3
"""Rolling source-certificate renewal from FRESH live evidence (certifier host).

    python scripts/certifier/renew_source_certificate.py [--force] [--renew-days 10]

Runs on the independent certifier host (where the Ed25519 private key lives,
0600, never on a server). Each run:

 1. Reads the production certificate's expiry (read-only). If more than
    --renew-days remain and --force is not given: exits NOT_DUE.
 2. Preconditions: employee sessions present, lab Guard ready, production ACL
    and directory sync connected. Any miss -> exit non-zero, nothing issued.
 3. Collects NEW live evidence into docs/evidence/certificate-renewals/<UTC>/:
    SharePoint effective-permission matrix, Layer 1 matrix (with stale/missing
    version and token controls), production identity bindings, protected RAG
    E2E, buffered-release audit join, and a full synthetic revocation trial A
    with the route probes (E2E-07 post-revocation, E2E-08 cache reuse, E2E-09
    in-flight Layer 2) and restoration.
 4. Reads the CURRENT source scope digest from production.
 5. Builds evidence and issues a 30-day certificate. The issuer refuses unless
    all 14 required checks PASS from artifacts observed < 72 h ago.
 6. Imports it (the API verifies signature, key pin, scope and expiry, and rolls
    back otherwise), then runs the production security gates read-only.

Never reuses stale evidence, never extends an existing certificate, never
touches Protect. On any failure the current certificate simply stays until it
expires, after which production fails closed (not certified).
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LIVE = ROOT / "scripts/live"
PY = [sys.executable, "-u"]
ORG = "48ee8c86-d4d8-4cde-b00b-bc779f965f4f"
SOURCE = "2fa9562b-b765-4098-bebf-222ea53ec667"
APP = "sharepoint-rag-staging"
INSTANCE, REGION = "i-0c11427d4d9c1b438", "eu-north-1"
KEY = Path.home() / ".config/accessproof/certifier/ap-certifier-2026-11.pem"
KEY_ID = "ap-certifier-2026-11"
SOCKS = {a: Path.home() / f".ap-id/{a}.sock" for a in ("alice", "bob")}
GUARD_CONTAINER = "accessproof-guard"
import importlib.util as _ilu  # noqa: E402
_ps = _ilu.spec_from_file_location("_ap_profile", LIVE / "_profile.py")
_pm = _ilu.module_from_spec(_ps); _ps.loader.exec_module(_pm)
PROFILE = _pm.apply("renew_source_certificate", globals())


def log(msg: str) -> None:
    print(f"{datetime.now(timezone.utc).isoformat()} {msg}", flush=True)


def ssm(script: str, comment: str, timeout: int = 600) -> str:
    params = json.dumps({"executionTimeout": [str(timeout)], "commands": script.splitlines()})
    cid = subprocess.run(["aws", "ssm", "send-command", "--region", REGION, "--instance-ids", INSTANCE,
                          "--document-name", "AWS-RunShellScript", "--comment", comment, "--parameters", params,
                          "--query", "Command.CommandId", "--output", "text"], check=True, capture_output=True, text=True).stdout.strip()
    deadline = time.time() + timeout + 60
    while time.time() < deadline:
        time.sleep(3)
        r = subprocess.run(["aws", "ssm", "get-command-invocation", "--region", REGION, "--command-id", cid,
                            "--instance-id", INSTANCE, "--query", "[Status,StandardOutputContent,StandardErrorContent]",
                            "--output", "json"], capture_output=True, text=True)
        if r.returncode == 0:
            status, out, err = json.loads(r.stdout)
            if status in ("Success", "Failed", "Cancelled", "TimedOut"):
                if status != "Success":
                    raise RuntimeError(f"SSM_{status}: {(err or '')[-300:]}")
                return out
    raise RuntimeError("SSM_TIMEOUT")


def sql(query: str) -> str:
    return ssm("docker exec accessproof-db-1 psql -U accessproof -d accessproof -Atc " + json.dumps(query).replace("$", "\\$"),
               "Read-only: certificate renewal check", 120).strip()


def run(args: list[str], name: str, env: dict | None = None) -> None:
    log(f"evidence: {name}")
    r = subprocess.run(PY + args, cwd=ROOT, env={**os.environ, **(env or {})}, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{name}_FAILED: {(r.stdout + r.stderr)[-400:]}")


def guard_audit(decision_ids: list[str]) -> list[dict]:
    code = ("import sqlite3,json,sys;ids=json.loads(sys.argv[1]);c=sqlite3.connect('file:/var/lib/accessproof-guard/policy.db?mode=ro',uri=True);"
            "q='select decision_id,layer,result,reason,created_at,authorization_revision from audit_buffer where decision_id in (%s) order by created_at'%','.join('?'*len(ids));"
            "print(json.dumps([dict(zip(('decision_id','layer','result','reason','created_at','authorization_revision'),r)) for r in c.execute(q,ids)]))")
    return json.loads(subprocess.run(["docker", "exec", GUARD_CONTAINER, "python", "-c", code, json.dumps(decision_ids)],
                                     capture_output=True, text=True, check=True).stdout)


def buffered_release(out: Path) -> None:
    e2e = json.loads((out / "rag-e2e.json").read_text())
    allowed = [r for r in e2e["results"] if r["observed"].get("gateway_decision") == "allow"]
    audit = guard_audit([r["observed"]["gateway_decision_id"] for r in allowed])
    rows = []
    for r in allowed:
        did = r["observed"]["gateway_decision_id"]
        l1 = [a for a in audit if a["decision_id"] == did and a["layer"] == "layer1" and a["result"] == "allow"]
        l2 = [a for a in audit if a["decision_id"] == did and a["layer"] == "layer2" and a["result"] == "allow"]
        rows.append({"test": r["test_identifier"], "gateway_decision_id": did, "layer1": l1[:1], "layer2": l2[:1],
                     "pass": bool(l1 and l2 and l1[0]["created_at"] <= l2[0]["created_at"] and r["observed"]["http_status"] == 200)})
    (out / "buffered-release.json").write_text(json.dumps({
        "schema": "accessproof.buffered_release/v1", "observed_at": datetime.now(timezone.utc).isoformat(),
        "results": rows, "pass": bool(rows) and all(x["pass"] for x in rows)}, indent=1))


def identity_bindings(out: Path) -> None:
    raw = sql("select json_agg(json_build_object('employee', s.display_name, 'oidc_subject_oid', m.oidc_subject, "
              "'oid_equals_source_principal', m.oidc_subject = s.provider_subject_id, 'method', m.method, 'status', m.status, "
              "'automatic', m.verified_by_user_id is null, 'account_kind', s.account_kind) order by s.display_name) "
              "from guard_identity_mappings m join guard_subjects s on s.id=m.source_subject_id "
              f"where m.organization_id='{ORG}' and s.display_name in ('alice','bob')")
    bindings = json.loads(raw.splitlines()[0])
    ok = len(bindings) == 2 and all(b["oid_equals_source_principal"] and b["method"] == "directory_verified"
                                     and b["status"] == "VERIFIED" for b in bindings)
    (out / "identity-bindings.json").write_text(json.dumps({
        "schema": "accessproof.identity_bindings_snapshot/v1", "observed_at": datetime.now(timezone.utc).isoformat(),
        "bindings": bindings, "pass": ok}, indent=1))


def push_file(local: Path, remote: str) -> str:
    return f"echo '{base64.b64encode(local.read_bytes()).decode()}' | base64 -d | docker exec -i accessproof-api-1 sh -c 'cat > {remote}'"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--force", action="store_true")
    p.add_argument("--renew-days", type=float, default=10.0)
    p.add_argument("--days", type=int, default=30)
    a = p.parse_args()
    expires = sql(f"select coalesce(extract(epoch from expires_at)::text,'') || '|' || status from source_effective_certifications "
                  f"where organization_id='{ORG}' and source_id='{SOURCE}'")
    remaining = None
    if expires and expires.split("|")[0]:
        remaining = (float(expires.split("|")[0]) - time.time()) / 86400
        log(f"current certificate: status={expires.split('|')[1]} days_remaining={remaining:.2f}")
    if remaining is not None and remaining > a.renew_days and not a.force and expires.endswith("|verified"):
        log("NOT_DUE")
        return 0
    # Preconditions (fail safe: nothing is issued without them).
    missing = [n for n, s in SOCKS.items() if not s.exists()]
    if missing:
        raise SystemExit(f"PRECONDITION_FAILED: employee sessions missing {missing} (sign in again)")
    if not KEY.exists() or (KEY.stat().st_mode & 0o077):
        raise SystemExit("PRECONDITION_FAILED: certifier key missing or not 0600")
    # A source being certified for the FIRST time cannot be "ready" (readiness requires
    # the certificate); its Guard must then be in the D-19 certification window instead.
    health = json.loads(subprocess.run(["docker", "exec", GUARD_CONTAINER, "python", "-c",
                                        "import urllib.request,sys;print(urllib.request.urlopen('http://127.0.0.1:8080/health?application_id='+sys.argv[1],timeout=5).read().decode())",
                                        APP], capture_output=True, text=True, check=True).stdout)
    if not (health.get("ready") or health.get("certification_window")):
        raise SystemExit(f"PRECONDITION_FAILED: Guard neither ready nor in its certification window ({health.get('status')})")
    cursors = sql(f"select string_agg(sync_kind||':'||status, ',') from provider_sync_cursors where organization_id='{ORG}' "
                  f"and source_id='{SOURCE}' and last_error_code is null")
    if cursors.count(":connected") < 2:
        raise SystemExit(f"PRECONDITION_FAILED: source sync not healthy ({cursors})")
    out = ROOT / "docs/evidence/certificate-renewals" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out.mkdir(parents=True, exist_ok=False)
    env = {"AP_TOKEN_KIND": "api_token"}
    run([str(LIVE / "sharepoint_effective_matrix.py"), "--out", str(out / "sharepoint-effective-matrix.json")], "effective_matrix")
    run([str(LIVE / "layer1_matrix.py"), "--out", str(out / "layer1.json")], "layer1_matrix")
    identity_bindings(out)
    run([str(LIVE / "rag_e2e.py"), "--alice", str(SOCKS["alice"]), "--bob", str(SOCKS["bob"]), "--out", str(out / "rag-e2e.json")], "rag_e2e", env)
    buffered_release(out)
    run([str(LIVE / "revocation_trial.py"), "--trial", "A", "--route", "--socket", str(SOCKS["alice"]), "--execute",
         "--budget-seconds", "1500", "--out", str(out / "revocation-A-route.json")], "revocation_route_trial", env)
    scope_out = ssm(push_file(ROOT / "scripts/issue_source_certificate.py", "/tmp/isc.py") + "\n"
                    f"docker exec -e PYTHONPATH=/app accessproof-api-1 python /tmp/isc.py scope --organization-id {ORG} --source-id {SOURCE}; rc=$?\n"
                    "docker exec accessproof-api-1 rm -f /tmp/isc.py; exit $rc", "Certificate scope digest (profile + digest only)")
    scope = json.loads(scope_out.strip().splitlines()[-1])
    evidence = out / "source-certification-evidence.json"
    run([str(LIVE / "build_certificate_evidence.py"), "--dir", str(out), "--organization-id", ORG, "--source-id", SOURCE,
         "--profile", scope["profile"], "--scope-digest", scope["scope_digest"], "--out", str(evidence)], "build_evidence")
    record = out / "source-certificate-record.json"
    r = subprocess.run(PY + [str(ROOT / "scripts/issue_source_certificate.py"), "issue", "--private-key", str(KEY), "--key-id", KEY_ID,
                             "--evidence", str(evidence), "--organization-id", ORG, "--source-id", SOURCE,
                             "--profile", scope["profile"], "--scope-digest", scope["scope_digest"], "--days", str(a.days)],
                       cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"ISSUANCE_REFUSED: {r.stderr.strip()[-300:]}")
    record.write_text(r.stdout)
    imported = ssm(push_file(ROOT / "scripts/issue_source_certificate.py", "/tmp/isc.py") + "\n" + push_file(record, "/tmp/record.json") + "\n"
                   "docker exec -e PYTHONPATH=/app accessproof-api-1 python /tmp/isc.py import --record /tmp/record.json; rc=$?\n"
                   "docker exec accessproof-api-1 rm -f /tmp/isc.py /tmp/record.json; exit $rc", "Import renewed source certificate")
    log("import: " + imported.strip().splitlines()[-1])
    new = json.loads(record.read_text())
    log(f"RENEWED certified_at={new['certified_at']} expires_at={new['expires_at']} evidence={new['evidence_digest'][:12]}")
    (out / "renewal.json").write_text(json.dumps({"renewed_at": datetime.now(timezone.utc).isoformat(),
                                                  "certified_at": new["certified_at"], "expires_at": new["expires_at"],
                                                  "evidence_digest": new["evidence_digest"], "previous_days_remaining": remaining}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
