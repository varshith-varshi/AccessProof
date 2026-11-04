#!/usr/bin/env python3
"""Live reference-route certification for the lab (synthetic data only).

    AP_ADMIN_EMAIL=... AP_ADMIN_PASSWORD=... python scripts/live/route_certification_run.py --out run.json

1. Verifies the installer deployment contract and network isolation locally.
2. Issues a one-time route challenge as the organization admin.
3. Runs the four real HTTP probes through the installed Gateway (allow,
   deny, tamper, layer2_revoke). For layer2_revoke, Alice's synthetic grant
   is revoked in SharePoint; the request is held until just before the
   control plane's next ACL sync and the lab model is paused (< Gateway model
   timeout) until the Guard installs the new revision, so Layer 1 allowed
   and the Layer 2 recheck must block. Alice's grant is always restored.
4. Submits the observations from INSIDE the Guard container (its machine
   credential never leaves it); the control plane corroborates them against
   the Guard's own audit records.
5. Runs the employee-route cutover probes and submits them the same way.

Never activates Protect (D-28: an owner approval is a separate step).
Stores ids, statuses, hashes and timestamps only.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
HERE = Path(__file__).resolve().parent


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ei, rt = _load("employee_identity"), _load("revocation_trial")
from apps.gateway.accessproof_gateway.challenge_agent import GatewayRouteChallenge, Probe  # noqa: E402
from apps.gateway.accessproof_gateway.customer_agent import verify_deployment_contract  # noqa: E402
from apps.gateway.accessproof_gateway.cutover_agent import (  # noqa: E402
    EmployeeRouteProbe, probe_customer_employee_route, verify_published_customer_route,
)
from apps.gateway.accessproof_gateway.installer import InstallationSpec  # noqa: E402

API = "https://api.accessproof.in"
ORG = rt.ORG
APP = rt.APP
LAB = Path.home() / "Downloads/sharepoint-rag-lab"
COMPOSE = LAB / "docker-compose.accessproof-reference.yml"
INSTALL = Path(os.environ.get("AP_GATEWAY_INSTALL_DIR", str(Path.home() / ".ap-id/ref-gw-r35")))
SPEC = Path.home() / ".config/accessproof/gateway-install/spec.json"
URL = "http://127.0.0.1:8191/v1/chat/completions"
MODEL = "sharepoint-rag-lab-model-1"
HOLD = Path.home() / "Downloads/sharepoint-rag-lab/witness/ap-hold"
NONCE_FILE = Path.home() / ".ap-id/route-challenge.nonce"
ENGINEERING_CANARY = "ACCESSPROOF_SYNTHETIC_ENGINEERING_BOB_20261027_P72"
SHARED_CANARY = "ACCESSPROOF_SYNTHETIC_SHARED_20261027_R18"
FINANCE_CANARY = "ACCESSPROOF_SYNTHETIC_FINANCE_ALICE_20261027_X51"

# Runs inside the Guard container: reads its own machine credential, posts the
# non-secret JSON given on stdin, prints only status and response body.
_GUARD_POST = r'''
import json, sys, time, httpx
req = json.load(sys.stdin)
c = json.load(open("/var/lib/accessproof-guard/credentials.json"))
url = c["control_plane_url"].rstrip("/") + req["path"].replace("{guard_id}", c["guard_id"])
body = req.get("body")
if body is not None:
    body["guard_id"] = c["guard_id"]
retry = set(req.get("retry_on", []))
with httpx.Client(timeout=20, trust_env=False, follow_redirects=False) as h:
    for attempt in range(req.get("attempts", 1)):
        r = h.request(req["method"], url, json=body, headers={"Authorization": "Bearer " + c["credential"]})
        try:
            data = r.json()
        except ValueError:
            data = {"raw": r.text[:300]}
        detail = data.get("detail") if isinstance(data, dict) else None
        code = detail.get("code") if isinstance(detail, dict) else detail
        if r.status_code == 409 and code in retry and attempt + 1 < req.get("attempts", 1):
            time.sleep(2)
            continue
        break
print(json.dumps({"status": r.status_code, "body": data}))
'''


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def guard_post(method: str, path: str, body: dict | None, *, retry_on=(), attempts=1) -> dict:
    out = subprocess.run(["docker", "exec", "-i", "accessproof-guard", "python", "-c", _GUARD_POST],
                         input=json.dumps({"method": method, "path": path, "body": body,
                                           "retry_on": list(retry_on), "attempts": attempts}),
                         capture_output=True, text=True, timeout=180)
    if out.returncode != 0:
        raise RuntimeError("GUARD_SUBMIT_FAILED")
    return json.loads(out.stdout.strip().splitlines()[-1])


def guard_id() -> str:
    code = "import json;print(json.load(open('/var/lib/accessproof-guard/credentials.json'))['guard_id'])"
    return subprocess.run(["docker", "exec", "accessproof-guard", "python", "-c", code],
                          capture_output=True, text=True, check=True).stdout.strip()


def chunk(name: str) -> dict:
    code = ("import sqlite3,json,os;c=sqlite3.connect('file:/data/index.db?mode=ro',uri=True);"
            "r=c.execute('select doc_id, chunk_id, text, version, attestation from chunks where name=? order by chunk_id limit 1',"
            f"('{name}',)).fetchone();"
            "print(json.dumps({'source_id':os.environ['LAB_SOURCE_ID'],'resource_id':r[0],'chunk_id':r[1],"
            "'content':r[2],'content_version':r[3],'content_attestation':r[4]}))")
    return json.loads(subprocess.run(["docker", "exec", "sharepoint-rag-lab-rag-1", "python", "-c", code],
                                     capture_output=True, text=True, check=True).stdout)


def guard_revision() -> int | None:
    return rt.guard_revision()


def acl_last_started() -> float:
    out = rt.ssm_sql("select extract(epoch from last_started_at) from provider_sync_cursors "
                     "where organization_id='" + ORG + "' and provider='microsoft365' and sync_kind='acl'")
    return float(out.strip())


class HeldTransport(httpx.BaseTransport):
    """Holds the layer2_revoke request until `release_at`, then pauses the model
    until the Guard installs a new authorization revision (max 27 s)."""

    def __init__(self, release_at: float, log: dict, decision_probe=None):
        self.inner = httpx.HTTPTransport()
        self.release_at, self.log = release_at, log
        # Returns the Guard's live Layer 1 decision for the revoked document.
        self.decision_probe = decision_probe

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and b"-layer2_revoke" in request.content:
            delay = self.release_at - time.time()
            if delay > 0:
                time.sleep(delay)
            HOLD.write_text("hold")
            self.log["layer2_revoke_sent_at"] = now()
            threading.Thread(target=self._pause_until_new_revision, daemon=True).start()
        return self.inner.handle_request(request)

    def _pause_until_new_revision(self) -> None:
        # The lab model bridge delays its answer while HOLD exists (no container
        # freeze: freezing broke the Gateway's model connection -> 503 before Layer 2).
        before = guard_revision()
        self.log["model_held_at"], self.log["revision_at_hold"] = now(), before
        start = time.monotonic()
        try:
            # Hold until the Guard returns a real DENY: during propagation it first
            # fails closed with 503 SOURCE_ACL_STALE (no Layer 2 audit), then denies.
            while time.monotonic() - start < 24.5:
                flipped = (self.decision_probe() == "DENY") if self.decision_probe else (guard_revision() != before)
                if flipped:
                    self.log["guard_decision_flipped_at"] = now()
                    time.sleep(0.3)
                    break
                time.sleep(0.4)
        finally:
            HOLD.unlink(missing_ok=True)
            self.log["model_released_at"] = now()


def wait_for_audit_delivery(nonce: str, timeout: float = 90.0) -> bool:
    """D-29: the verifier matches the Guard's UPLOADED audit records. Submit only
    after every local audit record of the four challenge requests (including the
    Layer 2 block, written when the held response returns) has been delivered."""
    import hashlib as _h
    prefix = "ap-challenge-" + _h.sha256(nonce.encode()).hexdigest()[:24] + "-"
    code = ("import sqlite3,json;c=sqlite3.connect('file:/var/lib/accessproof-guard/policy.db?mode=ro',uri=True);"
            f"r=c.execute(\"select count(*), sum(delivered_at is null), count(distinct request_id) from audit_buffer where request_id like '{prefix}%'\").fetchone();"
            "print(json.dumps(r))")
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = subprocess.run(["docker", "exec", "accessproof-guard", "python", "-c", code],
                             capture_output=True, text=True).stdout.strip()
        total, undelivered, requests = json.loads(out)
        if total and requests >= 4 and not undelivered:
            return True
        time.sleep(2)
    return False


def admin_session() -> dict:
    email, password = os.environ.get("AP_ADMIN_EMAIL"), os.environ.get("AP_ADMIN_PASSWORD")
    if not email or not password:
        sys.exit("AP_ADMIN_EMAIL and AP_ADMIN_PASSWORD are required")
    r = httpx.post(f"{API}/api/v1/auth/login", json={"email": email, "password": password}, timeout=30)
    r.raise_for_status()
    token = r.json().get("session_token")
    if not token:
        sys.exit("login did not return a session (MFA required?)")
    return {"Authorization": f"Bearer {token}", "X-Organization-ID": ORG, "Content-Type": "application/json"}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", required=True)
    p.add_argument("--attempts", type=int, default=3)
    a = p.parse_args()
    result: dict = {"schema": "accessproof.route_certification_run/v1", "started_at": now(), "attempts": []}

    def save():
        Path(a.out).write_text(json.dumps(result, indent=1))

    spec = InstallationSpec.parse(json.loads(SPEC.read_text()))
    installation = json.loads((INSTALL / "installation.json").read_text())
    resolved = json.loads(subprocess.run(["docker", "compose", "-f", str(COMPOSE), "-f", str(INSTALL / "gateway.override.json"),
                                          "config", "--format", "json"], capture_output=True, text=True, check=True).stdout)
    result["network_validation"] = verify_deployment_contract(installation=installation, spec=spec, resolved_compose=resolved)
    verify_published_customer_route(resolved_compose=resolved, rag_service=spec.rag_service, url=URL, gateway_port=spec.listen_port)
    result["deployment_sha256"], result["route_sha256"] = installation["deployment_sha256"], installation["route_sha256"]
    gid = guard_id()
    admin = admin_session()
    alice, bob = Path.home() / ".ap-id/alice.sock", Path.home() / ".ap-id/bob.sock"
    shared, finance = chunk("shared_control.txt"), chunk("finance_alice.txt")
    tampered = dict(shared, content=shared["content"] + "\nACCESSPROOF_FORGED_SOURCE_SENTINEL\n")
    trial = rt.Trial("A", str(alice))
    challenge = None
    try:
        for attempt in range(1, a.attempts + 1):
            log: dict = {"attempt": attempt}
            result["attempts"].append(log)
            if rt.RECOVERY.exists():
                trial.restore()
            # Wait until the Guard ALLOWs Alice on the finance document again.
            deadline = time.time() + 900
            while rt.guard_decision(ei.fetch(str(alice), "api_token"), finance["resource_id"]) != "ALLOW":
                if time.time() > deadline:
                    raise RuntimeError("Alice is not allowed on the finance document")
                time.sleep(10)
            # Revoke right after a sync, so the NEXT sync is the first to see it.
            while True:
                s0 = acl_last_started()
                age = time.time() - s0
                if 5 <= age <= 200:
                    break
                time.sleep(5)
            log["acl_last_started_epoch"] = s0
            log["revoke"] = trial.revoke()
            # r34 has no event-driven sync, and the next sync lands somewhere in
            # ~S0+295..330. Take back-to-back shots from S0+285: each fresh
            # challenge holds its layer2_revoke response until a real DENY or
            # 24 s. A 200 means the revocation was not yet detected (legitimate);
            # take the next shot. A Layer 1 denial ends this revocation cycle.
            while time.time() < s0 + 305:
                time.sleep(1)
            observed, shots = None, []
            log["shots"] = shots
            while time.time() < s0 + 380:
                resp = httpx.post(f"{API}/api/v1/current/ai-applications/{APP}/protection/challenge", headers=admin,
                                  json={"deployment_sha256": installation["deployment_sha256"],
                                        "route_sha256": installation["route_sha256"]}, timeout=30)
                resp.raise_for_status()
                challenge = resp.json()
                NONCE_FILE.write_text(challenge["nonce"])   # 0600 (umask) so a cutover can be resumed
                NONCE_FILE.chmod(0o600)
                shot: dict = {"challenge_id": challenge["challenge_id"], "issued_at": now()}
                shots.append(shot)
                a_tok, b_tok = ei.fetch(str(alice), "api_token"), ei.fetch(str(bob), "api_token")
                probes = (
                    Probe("allow", a_tok, [shared], (200,)),
                    Probe("deny", b_tok, [finance], (403,)),
                    Probe("tamper", a_tok, [tampered], (503,)),
                    Probe("layer2_revoke", a_tok, [finance], (403, 503)),
                )
                agent = GatewayRouteChallenge(url=URL, application_id=APP, challenge_nonce=challenge["nonce"],
                                              forbidden_canary="ACCESSPROOF_FORGED_SOURCE_SENTINEL",
                                              allowed_canary=SHARED_CANARY, probes=probes, timeout_seconds=60)
                probe_token = ei.fetch(str(alice), "api_token")
                client = httpx.Client(transport=HeldTransport(
                    0, shot, lambda: rt.guard_decision(probe_token, finance["resource_id"])),
                    base_url="http://127.0.0.1:8191", timeout=60, follow_redirects=False, trust_env=False)
                try:
                    observed = agent.run(client=client)
                    break
                except Exception as exc:
                    shot["probe_failure"] = f"{type(exc).__name__}: {str(exc)[:200]}"
                    save()
                    if "unexpected status 200" in shot["probe_failure"]:
                        continue          # held across no detection: take the next shot
                    break                 # Layer 1 already denied/stale: this cycle is spent
                finally:
                    client.close()
            if observed is None:
                log["probe_failure"] = shots[-1].get("probe_failure") if shots else "NO_SHOT"
                save()
                continue
            log["challenge_id"] = challenge["challenge_id"]
            log["probes"] = observed["probes"]
            payload = {"challenge_id": challenge["challenge_id"], "nonce": challenge["nonce"],
                       "deployment_sha256": installation["deployment_sha256"], "route_sha256": installation["route_sha256"],
                       "contract": "accessproof.gateway/v1", "observations": observed["probes"],
                       "customer_route_verified": True, "ingress_boundary_verified": True,
                       "retrieval_boundary_verified": True, "output_boundary_verified": True,
                       "alternate_route_blocked": True}
            log["audit_delivered_before_submit"] = wait_for_audit_delivery(challenge["nonce"])
            log["submit"] = guard_post("POST", f"/api/v1/guards/{{guard_id}}/rag-challenges/{challenge['challenge_id']}/submit",
                                       payload, retry_on=("GUARD_AUDIT_EVIDENCE_MISSING",), attempts=30)
            save()
            if log["submit"]["status"] == 202:
                break
        else:
            result["outcome"] = "CHALLENGE_NOT_VERIFIED"
            save()
            return 1
    finally:
        if rt.RECOVERY.exists():
            trial.restore()
            result["alice_grant_restored_at"] = now()
        save()
    # Cutover: real employee-route probes within 30 minutes of the verified test.
    # Wait for the restored grant to propagate (the Guard fails closed meanwhile).
    deadline = time.time() + 900
    while rt.guard_decision(ei.fetch(str(alice), "api_token"), finance["resource_id"]) != "ALLOW":
        if time.time() > deadline:
            break
        time.sleep(5)
    evidence, failures = None, []
    for _ in range(30):   # the small lab model does not always quote the canary
        route_probe = EmployeeRouteProbe(url=URL, allowed_token=ei.fetch(str(alice), "api_token"),
                                         denied_token=ei.fetch(str(bob), "api_token"),
                                         allowed_resources=[finance], denied_resources=[finance],
                                         allowed_canary=FINANCE_CANARY, forbidden_canary=ENGINEERING_CANARY)
        try:
            evidence = probe_customer_employee_route(installation=installation, spec=spec, resolved_compose=resolved,
                                                     nonce=challenge["nonce"], probe=route_probe,
                                                     client=httpx.Client(timeout=60, trust_env=False))
            break
        except Exception as exc:
            failures.append(f"{type(exc).__name__}: {str(exc)[:160]}")
            time.sleep(3)
    result["cutover_probe_failures"] = failures
    if evidence is None:
        result["outcome"] = "CUTOVER_PROBES_FAILED"
        save()
        return 1
    time.sleep(12)   # D-29: let the Guard upload the cutover audit records first
    receipt = {"challenge_id": challenge["challenge_id"], "nonce": challenge["nonce"],
               "deployment_sha256": installation["deployment_sha256"], "route_sha256": installation["route_sha256"],
               **evidence}
    result["cutover"] = guard_post("POST", f"/api/v1/guards/{{guard_id}}/rag-challenges/{challenge['challenge_id']}/cutover",
                                   receipt, retry_on=("CUSTOMER_CUTOVER_GUARD_AUDIT_MISMATCH",
                                                      "CUSTOMER_CUTOVER_DENIED_USER_NOT_GUARD_AUDITED",
                                                      "CUSTOMER_CUTOVER_TAMPER_NOT_GUARD_AUDITED"), attempts=30)
    result["guard_id"] = gid
    result["outcome"] = "CUTOVER_VERIFIED" if result["cutover"]["status"] == 202 else "CUTOVER_REFUSED"
    result["finished_at"] = now()
    save()
    print(json.dumps({"outcome": result["outcome"], "attempts": len(result["attempts"]),
                      "submit": result["attempts"][-1].get("submit", {}).get("status"),
                      "cutover": result["cutover"]["status"]}))
    return 0 if result["outcome"] == "CUTOVER_VERIFIED" else 1


if __name__ == "__main__":
    sys.exit(main())
