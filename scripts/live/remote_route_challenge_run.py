#!/usr/bin/env python3
"""Gate E route challenge for an organization whose Gateway runs in REMOTE mode
(TLS + ap-req-v1 application signatures), e.g. a fresh pilot organization.

    AP_PROFILE_FILE=<org profile> python scripts/live/remote_route_challenge_run.py --config pilot-challenge.json --out run.json

Identical security content to route_certification_run.py (event-driven):
four nonce-bound probes through the REAL Gateway (allow, deny, tamper,
layer2_revoke); for layer2_revoke the model answer is held after Layer 1, the
grant is revoked in SharePoint and the hold lasts until the Guard returns a
real DENY. Observations are submitted from INSIDE the organization's Guard
(its credential never leaves it) and corroborated by the control plane
against the Guard's uploaded audit. The only difference: the probe client
reaches the Gateway through a transport that adds TLS (pinned CA + SNI) and the
application request signature the remote Gateway requires. The response bytes
the agent judges are the Gateway's actual responses.

Never activates Protect. Restores the SharePoint grant in ``finally``.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import importlib.util
import json
import secrets
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

from apps.gateway.accessproof_gateway.challenge_agent import GatewayRouteChallenge, Probe  # noqa: E402


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ei, rt = _load("employee_identity"), _load("revocation_trial")      # rt honours AP_PROFILE_FILE
HOLD = Path.home() / "Downloads/sharepoint-rag-lab/witness/ap-hold"
SHARED_CANARY = "ACCESSPROOF_SYNTHETIC_SHARED_20261027_R18"
LOCAL_ORIGIN = "http://127.0.0.1:9444"     # what the agent sees; the transport carries it to the TLS Gateway

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


class SignedTLSHeldTransport(httpx.BaseTransport):
    def __init__(self, cfg: dict, log: dict, decision_probe):
        ctx = ssl.create_default_context(cafile=cfg["ca"])
        self.inner = httpx.HTTPTransport(verify=ctx)
        self.cfg, self.log, self.decision_probe = cfg, log, decision_probe
        self.secret = base64.urlsafe_b64decode(Path(cfg["secret_file"]).read_text().strip() + "==")

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        body = request.read()
        path = request.url.raw_path.decode()
        headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")}
        if request.method == "POST" and path.startswith("/v1/"):
            auth = request.headers.get("authorization", "")
            ts, nonce = str(int(time.time())), secrets.token_urlsafe(24)
            canon = "\n".join(["ap-req-v1", "POST", path, ts, nonce, hashlib.sha256(body).hexdigest(),
                               hashlib.sha256(auth.encode()).hexdigest()]).encode()
            sig = base64.urlsafe_b64encode(hmac.new(self.secret, canon, hashlib.sha256).digest()).rstrip(b"=").decode()
            headers.update({"X-AccessProof-Client": self.cfg["client_id"], "X-AccessProof-Timestamp": ts,
                            "X-AccessProof-Nonce": nonce, "X-AccessProof-Signature": sig})
            if b"-layer2_revoke" in body:
                HOLD.write_text("hold")
                self.log["layer2_revoke_sent_at"] = now()
                threading.Thread(target=self._hold_until_deny, daemon=True).start()
        target = httpx.Request(request.method, self.cfg["gateway"] + path, headers=headers, content=body,
                               extensions={**request.extensions, "sni_hostname": self.cfg["sni"]})
        return self.inner.handle_request(target)

    def _hold_until_deny(self) -> None:
        self.log["model_held_at"] = now()
        start = time.monotonic()
        try:
            while time.monotonic() - start < 24.5:
                if self.decision_probe() == "DENY":
                    self.log["guard_decision_flipped_at"] = now()
                    time.sleep(0.3)
                    break
                time.sleep(0.4)
        finally:
            HOLD.unlink(missing_ok=True)
            self.log["model_released_at"] = now()


def guard_post(container: str, method: str, path: str, body: dict | None, *, retry_on=(), attempts=1) -> dict:
    out = subprocess.run(["docker", "exec", "-i", container, "python", "-c", _GUARD_POST],
                         input=json.dumps({"method": method, "path": path, "body": body, "retry_on": list(retry_on),
                                           "attempts": attempts}), capture_output=True, text=True, timeout=180)
    if out.returncode != 0:
        raise RuntimeError("GUARD_SUBMIT_FAILED")
    return json.loads(out.stdout.strip().splitlines()[-1])


def wait_for_audit_delivery(container: str, nonce: str, timeout: float = 90.0) -> bool:
    prefix = "ap-challenge-" + hashlib.sha256(nonce.encode()).hexdigest()[:24] + "-"
    code = ("import sqlite3,json;c=sqlite3.connect('file:/var/lib/accessproof-guard/policy.db?mode=ro',uri=True);"
            f"r=c.execute(\"select count(*), sum(delivered_at is null), count(distinct request_id) from audit_buffer where request_id like '{prefix}%'\").fetchone();"
            "print(json.dumps(r))")
    deadline = time.time() + timeout
    while time.time() < deadline:
        total, undelivered, requests = json.loads(subprocess.run(["docker", "exec", container, "python", "-c", code],
                                                                 capture_output=True, text=True).stdout.strip())
        if total and requests >= 4 and not undelivered:
            return True
        time.sleep(2)
    return False


def resource(manifest: dict, name: str) -> dict:
    rid = next(d["resource_id"] for d in manifest["documents"] if d["name"] == name)
    c = next(x for x in manifest["chunks"] if x["resource_id"] == rid)
    return {"source_id": manifest["source_id"], "resource_id": rid, "chunk_id": c["chunk_id"], "content": c["content"],
            "content_version": c["content_version"], "content_attestation": c["content_attestation"]}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--attempts", type=int, default=3)
    p.add_argument("--revoke-lead", type=float, default=28.0)
    a = p.parse_args()
    cfg = json.loads(Path(a.config).read_text())
    result: dict = {"schema": "accessproof.remote_route_challenge_run/v1", "started_at": now(), "attempts": [],
                    "organization_id": cfg["organization_id"], "application_id": cfg["application_id"]}

    def save():
        Path(a.out).write_text(json.dumps(result, indent=1))

    login = httpx.post(cfg["api"] + "/api/v1/auth/login", timeout=30,
                       json={"email": cfg["admin_email"], "password": Path(cfg["admin_password_file"]).read_text().strip()})
    login.raise_for_status()
    admin = {"Authorization": "Bearer " + login.json()["session_token"], "X-Organization-ID": cfg["organization_id"]}
    installation = json.loads(Path(cfg["installation"]).read_text())["manifest"]
    alice, bob = str(Path.home() / ".ap-id/alice.sock"), str(Path.home() / ".ap-id/bob.sock")
    trial = rt.Trial("A", alice)
    challenge = None
    try:
        for attempt in range(1, a.attempts + 1):
            log: dict = {"attempt": attempt}
            result["attempts"].append(log)
            if rt.RECOVERY.exists():
                trial.restore()
            manifest = json.loads(Path(cfg["manifest"]).read_text())      # fresh pilot attestations
            shared, finance = resource(manifest, "shared_control.txt"), resource(manifest, "finance_alice.txt")
            tampered = dict(shared, content=shared["content"] + "\nACCESSPROOF_FORGED_SOURCE_SENTINEL\n")
            deadline = time.time() + 900
            while rt.guard_decision(ei.fetch(alice, "api_token"), finance["resource_id"]) != "ALLOW":
                if time.time() > deadline:
                    raise RuntimeError("Alice is not allowed on the finance document")
                time.sleep(10)
            resp = httpx.post(f"{cfg['api']}/api/v1/current/ai-applications/{cfg['application_id']}/protection/challenge",
                              headers=admin, timeout=30, json={"deployment_sha256": installation["deployment_sha256"],
                                                               "route_sha256": installation["route_sha256"]})
            resp.raise_for_status()
            challenge = resp.json()
            log["challenge_id"] = challenge["challenge_id"]
            a_tok, b_tok = ei.fetch(alice, "api_token"), ei.fetch(bob, "api_token")
            probes = (Probe("allow", a_tok, [shared], (200,)), Probe("deny", b_tok, [finance], (403,)),
                      Probe("tamper", a_tok, [tampered], (503,)), Probe("layer2_revoke", a_tok, [finance], (403, 503)))
            agent = GatewayRouteChallenge(url=LOCAL_ORIGIN + "/v1/chat/completions", application_id=cfg["application_id"],
                                          challenge_nonce=challenge["nonce"], forbidden_canary="ACCESSPROOF_FORGED_SOURCE_SENTINEL",
                                          allowed_canary=SHARED_CANARY, probes=probes, timeout_seconds=60)
            probe_token = ei.fetch(alice, "api_token")
            log["revoke"] = trial.revoke()
            log["revoked_at"] = now()
            time.sleep(max(0.0, a.revoke_lead - 9.0))
            client = httpx.Client(transport=SignedTLSHeldTransport(cfg["gateway_client"], log,
                                                                   lambda: rt.guard_decision(probe_token, finance["resource_id"])),
                                  base_url=LOCAL_ORIGIN, timeout=60, follow_redirects=False, trust_env=False)
            try:
                observed = agent.run(client=client)
            except Exception as exc:
                log["probe_failure"] = f"{type(exc).__name__}: {str(exc)[:200]}"
                save()
                trial.restore()
                continue
            finally:
                client.close()
            log["probes"] = observed["probes"]
            payload = {"challenge_id": challenge["challenge_id"], "nonce": challenge["nonce"],
                       "deployment_sha256": installation["deployment_sha256"], "route_sha256": installation["route_sha256"],
                       "contract": "accessproof.gateway/v1", "observations": observed["probes"],
                       "customer_route_verified": True, "ingress_boundary_verified": True,
                       "retrieval_boundary_verified": True, "output_boundary_verified": True, "alternate_route_blocked": True}
            log["audit_delivered_before_submit"] = wait_for_audit_delivery(cfg["guard_container"], challenge["nonce"])
            log["submit"] = guard_post(cfg["guard_container"], "POST",
                                       f"/api/v1/guards/{{guard_id}}/rag-challenges/{challenge['challenge_id']}/submit",
                                       payload, retry_on=("GUARD_AUDIT_EVIDENCE_MISSING",), attempts=30)
            save()
            if log["submit"]["status"] == 202:
                break
        else:
            result["outcome"] = "CHALLENGE_NOT_VERIFIED"
            return 1
        result["outcome"] = "ROUTE_CHALLENGE_VERIFIED"
        return 0
    finally:
        if rt.RECOVERY.exists():
            trial.restore()
            result["alice_grant_restored_at"] = now()
        result["finished_at"] = now()
        save()
        print(json.dumps({"outcome": result.get("outcome"), "attempts": len(result["attempts"]),
                          "submit": (result["attempts"][-1].get("submit") or {}).get("status") if result["attempts"] else None}))


if __name__ == "__main__":
    sys.exit(main())
