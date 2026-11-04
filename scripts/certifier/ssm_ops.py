"""Client for the purpose-built certifier SSM documents (no AWS-RunShellScript).

    from ssm_ops import read_only, import_payload, rag_host_probe

Production read-only operations, the single import path and the staging probes
all go through the named documents in ``deploy/certifier/ssm``. The calling
identity (AWS_PROFILE=accessproof-certifier, IAM Roles Anywhere) may run ONLY these
documents.

Pre-validation (owner session only, before the documents exist):
AP_SSM_RENDER_LOCAL=1 renders the committed document exactly as SSM substitutes
parameters (after checking each value against its allowedPattern/allowedValues)
and sends it through AWS-RunShellScript, which proves the real document content.
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import time
from pathlib import Path

REGION = "eu-north-1"
PRODUCTION, STAGING = "i-0c11427d4d9c1b438", "i-0e6d2256a1e5a6f67"
DOCS = Path(__file__).resolve().parents[2] / "deploy/certifier/ssm"
READ_ONLY = "AccessProof-Certifier-ProductionReadOnly"
IMPORT = "AccessProof-Certifier-ProductionImport"
PROBE = "AccessProof-Certifier-RagHostProbe"
PART = 1000


class SsmOpError(RuntimeError):
    pass


def _render(document: str, params: dict) -> list[str]:
    d = json.loads((DOCS / f"{document}.json").read_text())
    values = {}
    for name, spec in d["parameters"].items():
        value = str(params.get(name, spec.get("default", "")))
        if "allowedValues" in spec and value not in spec["allowedValues"]:
            raise SsmOpError(f"PARAMETER_NOT_ALLOWED:{name}")
        if "allowedPattern" in spec and not re.fullmatch(spec["allowedPattern"], value):
            raise SsmOpError(f"PARAMETER_PATTERN:{name}")
        values[name] = value
    lines = d["mainSteps"][0]["inputs"]["runCommand"]
    return [re.sub(r"\{\{ *(\w+) *\}\}", lambda m: values[m.group(1)], line) for line in lines]


def run(document: str, instance: str, params: dict, comment: str, timeout: int = 600) -> str:
    unknown = set(params) - set(json.loads((DOCS / f"{document}.json").read_text())["parameters"])
    if unknown:
        raise SsmOpError(f"UNKNOWN_PARAMETERS:{sorted(unknown)}")
    if os.environ.get("AP_SSM_RENDER_LOCAL") == "1":
        name, ssm_params = "AWS-RunShellScript", {"commands": _render(document, params), "executionTimeout": [str(timeout)]}
    else:
        _render(document, params)          # same validation client-side; SSM enforces it again
        name, ssm_params = document, {k: [str(v)] for k, v in params.items()}
    cid = subprocess.run(["aws", "ssm", "send-command", "--region", REGION, "--instance-ids", instance,
                          "--document-name", name, "--comment", comment[:100], "--parameters", json.dumps(ssm_params),
                          "--query", "Command.CommandId", "--output", "text"],
                         check=True, capture_output=True, text=True).stdout.strip()
    deadline = time.time() + timeout + 60
    while time.time() < deadline:
        time.sleep(2)
        r = subprocess.run(["aws", "ssm", "get-command-invocation", "--region", REGION, "--command-id", cid,
                            "--instance-id", instance, "--output", "json"], capture_output=True, text=True)
        if r.returncode == 0:
            inv = json.loads(r.stdout)
            if inv["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
                if inv["Status"] != "Success":
                    raise SsmOpError(f"SSM_{inv['Status']}: {(inv.get('StandardErrorContent') or '')[-300:]}")
                return inv.get("StandardOutputContent", "")
    raise SsmOpError("SSM_TIMEOUT")


def read_only(operation: str, **params) -> str:
    return run(READ_ONLY, PRODUCTION, {"operation": operation, **params}, f"read-only: {operation}").strip()


def import_payload(operation: str, payload: dict, **params) -> str:
    raw = base64.b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()).decode()
    parts = [raw[i:i + PART] for i in range(0, len(raw), PART)]
    if len(parts) > 8:
        raise SsmOpError("PAYLOAD_TOO_LARGE")
    chunks = {f"payload{i + 1}": p for i, p in enumerate(parts)}
    return run(IMPORT, PRODUCTION, {"operation": operation, **params, **chunks}, f"import: {operation}")


def rag_host_probe(probe: str, **params) -> str:
    return run(PROBE, STAGING, {"probe": probe, **params}, f"rag host probe: {probe}")
