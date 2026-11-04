#!/usr/bin/env python3
"""Employee-route cutover for an already VERIFIED route challenge (within 30 min).

    python scripts/live/route_cutover_only.py --run route-certification-run-N.json --out cutover.json

Waits until the Guard is healthy and ALLOWs the authorized document, then runs
the official cutover probes (allow / deny / tamper) under the challenge's bound
request ids and submits from inside the Guard container. Never activates Protect.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import time
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("rcr", HERE / "route_certification_run.py")
rcr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rcr)
ENGINEERING_CANARY = "ACCESSPROOF_SYNTHETIC_ENGINEERING_BOB_20261027_P72"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--run", required=True)
    p.add_argument("--nonce-file", required=True, help="0600 file holding the verified challenge nonce")
    p.add_argument("--out", required=True)
    p.add_argument("--tries", type=int, default=30)
    a = p.parse_args()
    run = json.loads(Path(a.run).read_text())
    challenge_id = next(x["challenge_id"] for x in reversed(run["attempts"]) if x.get("submit", {}).get("status") == 202)
    nonce = Path(a.nonce_file).read_text().strip()
    spec_ = rcr.InstallationSpec.parse(json.loads(rcr.SPEC.read_text()))
    installation = json.loads((rcr.INSTALL / "installation.json").read_text())
    resolved = json.loads(rcr.subprocess.run(["docker", "compose", "-f", str(rcr.COMPOSE), "-f", str(rcr.INSTALL / "gateway.override.json"),
                                              "config", "--format", "json"], capture_output=True, text=True, check=True).stdout)
    alice, bob = Path.home() / ".ap-id/alice.sock", Path.home() / ".ap-id/bob.sock"
    finance = rcr.chunk("finance_alice.txt")
    deadline = time.time() + 600
    while rcr.rt.guard_decision(rcr.ei.fetch(str(alice), "api_token"), finance["resource_id"]) != "ALLOW":
        if time.time() > deadline:
            sys.exit("Guard never returned ALLOW for the authorized document")
        time.sleep(5)
    out = {"challenge_id": challenge_id, "started_at": rcr.now(), "failures": []}
    evidence = None
    for _ in range(a.tries):
        probe = rcr.EmployeeRouteProbe(url=rcr.URL, allowed_token=rcr.ei.fetch(str(alice), "api_token"),
                                       denied_token=rcr.ei.fetch(str(bob), "api_token"),
                                       allowed_resources=[finance], denied_resources=[finance],
                                       allowed_canary=rcr.FINANCE_CANARY, forbidden_canary=ENGINEERING_CANARY)
        try:
            evidence = rcr.probe_customer_employee_route(installation=installation, spec=spec_, resolved_compose=resolved,
                                                         nonce=nonce, probe=probe, client=httpx.Client(timeout=60, trust_env=False))
            break
        except Exception as exc:
            out["failures"].append(f"{type(exc).__name__}: {str(exc)[:160]}")
            time.sleep(2)
    if evidence is None:
        out["outcome"] = "CUTOVER_PROBES_FAILED"
        Path(a.out).write_text(json.dumps(out, indent=1))
        return 1
    out["evidence"] = evidence
    rcr.wait_for_audit_delivery_prefix = None
    time.sleep(12)   # let the Guard upload the cutover audits (same D-29 race)
    receipt = {"challenge_id": challenge_id, "nonce": nonce, "deployment_sha256": installation["deployment_sha256"],
               "route_sha256": installation["route_sha256"], **evidence}
    out["cutover"] = rcr.guard_post("POST", f"/api/v1/guards/{{guard_id}}/rag-challenges/{challenge_id}/cutover", receipt,
                                    retry_on=("CUSTOMER_CUTOVER_GUARD_AUDIT_MISMATCH", "CUSTOMER_CUTOVER_DENIED_USER_NOT_GUARD_AUDITED",
                                              "CUSTOMER_CUTOVER_TAMPER_NOT_GUARD_AUDITED"), attempts=30)
    out["outcome"] = "CUTOVER_VERIFIED" if out["cutover"]["status"] == 202 else "CUTOVER_REFUSED"
    out["finished_at"] = rcr.now()
    Path(a.out).write_text(json.dumps(out, indent=1))
    print(json.dumps({"outcome": out["outcome"], "tries": len(out["failures"]) + 1, "cutover": out["cutover"]["status"]}))
    return 0 if out["outcome"] == "CUTOVER_VERIFIED" else 1


if __name__ == "__main__":
    sys.exit(main())
