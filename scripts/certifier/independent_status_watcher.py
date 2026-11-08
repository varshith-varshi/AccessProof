#!/usr/bin/env python3
"""Laptop-independent, read-only source/route certificate status watcher.

Runs on the isolated certifier EC2 under its restricted execution role.
Invokes ONLY a fixed, versioned AccessProof SSM ProductionReadOnly document
with pinned organization/source/application IDs. No certificate signatures,
imports, tokens, private keys, Gateway or Guard access. Fails closed.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

try:
    from scripts.certifier import independent_host_preflight as hp
except ModuleNotFoundError:
    import independent_host_preflight as hp  # deployed sibling script on EC2

REGION = "eu-north-1"
PRODUCTION = "i-0c11427d4d9c1b438"
DOC = "AccessProof-Certifier-ProductionReadOnly"
ORG = "48ee8c86-d4d8-4cde-b00b-bc779f965f4f"
SOURCE = "2fa9562b-b765-4098-bebf-222ea53ec667"
APP = "sharepoint-rag-staging"
# All registered production certification scopes monitored by this host.
# Explicit allowlist: no arbitrary caller-selected organizations or sources.
MONITORED = {
    "reference": {"organization_id": ORG, "source_id": SOURCE, "application_id": APP},
    "pilot": {
        "organization_id": "0fb98b25-bd7d-445e-a192-4ff8ee730760",
        "source_id": "4eb6863f-297a-4681-b913-30c48f9f916a",
        "application_id": "pilot-hr-rag",
    },
}
TERMINAL = {"Success", "Cancelled", "TimedOut", "Failed", "Cancelling"}


def aws(*args: str, timeout: int = 25) -> dict:
    if os.environ.get("AWS_PROFILE") != "accessproof-certifier":
        raise RuntimeError("RESTRICTED_CERTIFIER_AWS_PROFILE_REQUIRED")
    if any(os.getenv(x) for x in (
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "AWS_SECURITY_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE")):
        raise RuntimeError("STATIC_CREDENTIAL_OVERRIDE_REFUSED")
    run = subprocess.run(["aws", *args, "--region", REGION, "--output", "json"],
                         capture_output=True, text=True, timeout=timeout)
    if run.returncode:
        raise RuntimeError("AWS_READ_ONLY_OPERATION_FAILED")
    value = json.loads(run.stdout)
    if not isinstance(value, dict):
        raise RuntimeError("INVALID_AWS_RESULT")
    return value


def read_only(operation: str, *, organization_id: str, source_id: str = "",
              application_id: str = "") -> str:
    if operation not in {"certificate_status", "route_status"}:
        raise ValueError("UNAPPROVED_STATUS_OPERATION")
    scope = next((target for target in MONITORED.values()
                  if target["organization_id"] == organization_id), None)
    if scope is None:
        raise ValueError("UNAPPROVED_ORGANIZATION")
    params = {"operation": [operation], "organizationId": [organization_id]}
    if operation == "certificate_status":
        if source_id != scope["source_id"] or application_id:
            raise ValueError("SOURCE_BINDING_INVALID")
        params["sourceId"] = [source_id]
    else:
        if application_id != scope["application_id"] or source_id:
            raise ValueError("APP_BINDING_INVALID")
        params["applicationId"] = [application_id]
    sent = aws("ssm", "send-command", "--document-name", DOC,
               "--instance-ids", PRODUCTION, "--parameters",
               json.dumps(params, separators=(",", ":"), sort_keys=True),
               "--comment", "Isolated certifier read-only " + operation)
    cid = sent.get("Command", {}).get("CommandId")
    if not isinstance(cid, str) or not cid:
        raise RuntimeError("NO_SSM_COMMAND_ID")
    for _ in range(25):
        time.sleep(2)
        data = aws("ssm", "get-command-invocation", "--command-id", cid,
                   "--instance-id", PRODUCTION)
        state = data.get("Status")
        if state == "Success":
            if data.get("ResponseCode") != 0:
                raise RuntimeError("SSM_READONLY_NONZERO")
            return str(data.get("StandardOutputContent", "")).strip()
        if state in TERMINAL:
            raise RuntimeError("SSM_READONLY_" + str(state).upper())
    raise RuntimeError("SSM_READONLY_TIMEOUT")


def parse_source(raw: str, now: float) -> dict:
    try:
        record = next(x.strip() for x in raw.splitlines() if "|" in x)
        expiry, status = record.split("|", 1)
        remaining = (float(expiry) - now) / 86400
        if status not in {"verified", "certified", "VALID", "active"}:
            return {"state": "UNVERIFIED", "days_remaining": round(remaining, 3)}
        return {"state": "VALID" if remaining > 0 else "EXPIRED",
                "days_remaining": round(remaining, 3),
                "renewal_window": remaining <= 10}
    except (StopIteration, TypeError, ValueError):
        return {"state": "UNOBSERVABLE"}


def parse_routes(raw: str, now: datetime) -> dict:
    try:
        obj = json.loads(raw)
        if not isinstance(obj, dict) or not isinstance(obj.get("routes"), list):
            raise ValueError("missing routes")
        routes = obj["routes"]
        current = [r for r in routes if r.get("state") == "VALID"]
        def remaining(x):
            return (datetime.fromisoformat(x["expires_at"].replace("Z", "+00:00")) - now).total_seconds() / 86400
        valid_days = [remaining(r) for r in current]
        return {"state": "CERTIFIED" if obj.get("certified") and valid_days and min(valid_days)>0 else "NOT_CERTIFIED",
                "valid_route_count": len(current),
                "historically_invalidated_count": sum(r.get("state") == "INVALIDATED" for r in routes),
                "earliest_valid_expiry_days": round(min(valid_days), 3) if valid_days else None,
                "renewal_window": bool(valid_days) and min(valid_days) <= 2}
    except (ValueError, TypeError, KeyError, AttributeError):
        return {"state": "UNOBSERVABLE"}


def watch(*, instance: str, role_arn: str, key_arn: str) -> dict:
    readiness = hp.report(expected_instance=instance, role_arn=role_arn, key_arn=key_arn)
    if readiness["host_prerequisites"] != "PASS":
        raise RuntimeError("HOST_IDENTITY_KMS_PREFLIGHT_FAILED")
    now = datetime.now(timezone.utc)
    scopes: dict[str, dict] = {}
    for label, cfg in MONITORED.items():
        # A failure in one organization must be visible without hiding the
        # other organization's state. No secret/token/PII is printed.
        try:
            source = parse_source(
                read_only("certificate_status", organization_id=cfg["organization_id"],
                          source_id=cfg["source_id"]), now.timestamp())
        except (RuntimeError, ValueError, OSError) as exc:
            source = {"state": "UNOBSERVABLE", "error_type": type(exc).__name__}
        try:
            routes = parse_routes(
                read_only("route_status", organization_id=cfg["organization_id"],
                          application_id=cfg["application_id"]), now)
        except (RuntimeError, ValueError, OSError) as exc:
            routes = {"state": "UNOBSERVABLE", "error_type": type(exc).__name__}
        scopes[label] = {"source": source, "routes": routes,
                         "certification_healthy": (source["state"] == "VALID"
                                                   and routes["state"] == "CERTIFIED")}

    # The production documents/API, not this watcher, remain the authority on
    # certification. Never report healthy if a monitored scope is missing,
    # expired, uncertified or unobservable.
    healthy = len(scopes) == len(MONITORED) and all(
        entry["certification_healthy"] for entry in scopes.values())
    return {"schema": "accessproof.independent_certificate_status/v2",
            "checked_at": now.isoformat(),
            "monitored_scope_count": len(scopes), "scopes": scopes,
            "monitor_status": "UP" if healthy else "DEGRADED",
            "signing_enabled": False, "renewal_independent": False}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--expected-instance-id", required=True)
    p.add_argument("--expected-role-arn", required=True)
    p.add_argument("--kms-key-arn", required=True)
    a = p.parse_args()
    try:
        result = watch(instance=a.expected_instance_id, role_arn=a.expected_role_arn,
                       key_arn=a.kms_key_arn)
        print(json.dumps(result, sort_keys=True), flush=True)
        return 0 if result["monitor_status"] == "UP" else 2
    except Exception as exc:
        print(json.dumps({"schema":"accessproof.independent_certificate_status/v1",
                          "monitor_status":"DEGRADED", "cause":type(exc).__name__,
                          "signing_enabled":False, "renewal_independent":False}), flush=True)
        return 2


if __name__ == "__main__":
    sys.exit(main())
