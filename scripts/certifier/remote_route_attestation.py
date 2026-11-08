#!/usr/bin/env python3
"""Daily verification of production-certified REMOTE RAG routes (certifier host).

    python scripts/certifier/remote_route_attestation.py [--config ~/.config/accessproof/remote-routes.json]

For every configured route:
  * if its certificate expires within --recertify-days (default 2; certificates
    last 7 days), run the FULL 14-check certification (includes one live
    revocation) and import the new certificate into production;
  * otherwise sign a LIVE attestation of the route's current binding and apply
    it in production: a changed configuration INVALIDATES the certificate
    (Gate E fails) until re-certified.
A route that cannot be observed gets no attestation; production marks it
ATTESTATION_STALE after 24 h and Gate E fails closed. Nothing is ever extended.

Config (0600): [{"name", "organization_id", "application_id", "route_url", "rag_exec",
  "rag_ca_path"?, "rag_gateway_url"?, "gateway_outage"?, "source_evidence"?, "env"?: {...}}]
Current certificates: ~/.ap-id/route-certs/<name>.certificate.json (updated on re-certification).
Log: ~/.ap-id/route-attestation.log (one JSON line per route per run).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CERTIFIER = ROOT / "scripts/live/remote_route_certification.py"
STATE = Path.home() / ".ap-id/route-certs"
LOG = Path.home() / ".ap-id/route-attestation.log"


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def log(entry: dict) -> None:
    LOG.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with LOG.open("a") as fh:
        fh.write(json.dumps({"at": now(), **entry}) + "\n")
    print(json.dumps(entry), flush=True)


sys.path.insert(0, str(Path(__file__).resolve().parent))
import ssm_ops  # noqa: E402  (purpose-built SSM documents; no AWS-RunShellScript)

sys.path.insert(0, str(ROOT))
from scripts.certifier.renewal_watchdog import employee_sessions  # noqa: E402


def employee_sessions_ready(sessions: dict | None = None) -> tuple[bool, list[str]]:
    """Full re-certification asks live Alice/Bob questions. Refuse to start it
    (and to stop Gateway/Guard or revoke SharePoint access) without both sessions."""
    sessions = employee_sessions(Path.home()) if sessions is None else sessions
    missing = sorted(a for a, info in sessions.items() if info.get("status") == "UNAVAILABLE")
    return (not missing and len(sessions) >= 2), missing


def production(action: str, route: dict, document: dict) -> dict:
    op = {"import": "route_certificate_import", "attest": "route_attestation"}[action]
    out = ssm_ops.import_payload(op, document, organizationId=route["organization_id"],
                                 applicationId=route["application_id"])
    line = next((x for x in out.splitlines() if x.startswith('{"ok"')), None)
    return json.loads(line) if line else {"ok": False, "error": "NO_RESPONSE"}


def certifier(route: dict, *extra: str) -> subprocess.CompletedProcess:
    cmd = ["uv", "run", "--extra", "dev", "python", "-u", str(CERTIFIER), "--route-url", route["route_url"],
           "--rag-exec", route["rag_exec"]]
    for opt in ("rag_ca_path", "rag_gateway_url", "gateway_outage", "source_evidence"):
        if route.get(opt):
            cmd += ["--" + opt.replace("_", "-"), route[opt]]
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"} | dict(route.get("env") or {})
    return subprocess.run(cmd + list(extra), cwd=ROOT, env=env, capture_output=True, text=True, timeout=3000)


_TRANSIENT_OBSERVATION_MARKERS = (
    "ConnectionResetError", "ConnectionRefusedError", "Connection reset by peer",
    "Connection refused", "[Errno 104]", "[Errno 111]", "TimeoutError",
    "timed out", "Temporary failure in name resolution",
)


def observe_attestation(route: dict, cert_path: Path, *, retries: int = 2) -> tuple[dict | None, str]:
    """Retry ONLY a missing attestation caused by transport failure.

    A signed mismatch, denied authorization, malformed attestation, or failed
    production import is never converted to success or retried. Each attempt
    must gather a new LIVE binding; no cached evidence is used.
    """
    for attempt in range(retries + 1):
        run = certifier(route, "--attest", str(cert_path))
        candidate = None
        if run.stdout.strip():
            try:
                value = json.loads(run.stdout.strip().splitlines()[-1])
                candidate = value if isinstance(value, dict) else None
            except (ValueError, IndexError):
                pass
        if candidate and isinstance(candidate.get("signature"), str):
            # An observable binding mismatch must be surfaced to production,
            # so it can invalidate the old route. Never reattempt mismatches.
            return candidate, "SIGNED"
        error = (run.stderr or "UNOBSERVABLE")[-1500:]
        # No exception traceback or credential-bearing stderr leaves this
        # helper: only a small stable error class is logged downstream.
        transient = any(marker in error for marker in _TRANSIENT_OBSERVATION_MARKERS)
        if not transient:
            return None, "OBSERVATION_FAILED"
        if attempt == retries:
            return None, "TRANSIENT_ROUTE_UNAVAILABLE"
        time.sleep((attempt + 1) * 3)
    return None, "TRANSIENT_ROUTE_UNAVAILABLE"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", default=str(Path.home() / ".config/accessproof/remote-routes.json"))
    p.add_argument("--recertify-days", type=float, default=2.0)
    p.add_argument("--only")
    a = p.parse_args()
    cfg_path = Path(a.config)
    if cfg_path.stat().st_mode & 0o077:
        raise SystemExit("config must be 0600")
    routes = json.loads(cfg_path.read_text())
    failures = 0
    for route in routes:
        if a.only and route["name"] != a.only:
            continue
        cert_path = STATE / f"{route['name']}.certificate.json"
        try:
            cert = json.loads(cert_path.read_text())
            remaining = (datetime.fromisoformat(cert["expires_at"]) - datetime.now(timezone.utc)).total_seconds() / 86400
            if remaining <= a.recertify_days:
                ready, missing = employee_sessions_ready()
                if not ready:
                    failures += 1
                    log({"route": route["name"], "action": "recertify", "ok": False,
                         "detail": "EMPLOYEE_SESSION_UNAVAILABLE:" + ",".join(missing),
                         "days_remaining": round(remaining, 2)})
                    continue
                out = STATE / f"{route['name']}.run-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json"
                r = certifier(route, "--issue", "--out", str(out))
                new = Path(str(out) + ".certificate.json")
                if r.returncode != 0 or not new.exists() or json.loads(new.read_text())["status"] != "CERTIFIED":
                    failures += 1
                    log({"route": route["name"], "action": "recertify", "ok": False,
                         "detail": (r.stdout + r.stderr)[-300:]})
                    continue
                result = production("import", route, json.loads(new.read_text()))
                if result.get("ok"):
                    new.replace(cert_path)
                log({"route": route["name"], "action": "recertify+import", "ok": result.get("ok"),
                     "event": result.get("event") or result.get("error")})
                failures += 0 if result.get("ok") else 1
                continue
            att, observation_state = observe_attestation(route, cert_path)
            if not att:
                failures += 1
                log({"route": route["name"], "action": "attest", "ok": False,
                     "detail": observation_state})
                continue
            result = production("attest", route, att)
            state = [x["state"] for x in (result.get("status") or {}).get("routes", []) if x["fingerprint"] == cert["fingerprint"]]
            log({"route": route["name"], "action": "attest", "ok": result.get("ok"), "matches": att["matches"],
                 "changed_fields": att["changed_fields"], "production_state": state[:1], "days_remaining": round(remaining, 2)})
            failures += 0 if (result.get("ok") and att["matches"]) else 1
        except Exception as exc:                       # recorded; the route goes stale and fails closed
            failures += 1
            log({"route": route["name"], "action": "error", "ok": False, "detail": f"{type(exc).__name__}: {str(exc)[:200]}"})
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
