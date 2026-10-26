from __future__ import annotations
from typing import Any
import json
import os
import sys
import time
import urllib.request
import urllib.error

BASE = os.environ["AP_API_URL"].rstrip("/")
HEADERS = {
    "Authorization": f"Bearer {os.environ['AP_API_TOKEN']}",
    "X-Organization-ID": os.environ["AP_ORG_ID"],
    "Content-Type": "application/json",
}


def request(method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
    req = urllib.request.Request(
        BASE + path,
        method=method,
        headers=HEADERS,
        data=json.dumps(payload).encode() if payload is not None else None,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"AccessProof API error {e.code}: {body}", file=sys.stderr)
        sys.exit(3)


payload = {
    "project_id": os.environ["AP_PROJECT_ID"],
    "suite_id": os.environ["AP_SUITE_ID"],
    "release": os.environ["AP_RELEASE"],
    "git_sha": os.environ.get("AP_GIT_SHA"),
}
if os.environ.get("AP_SOURCE_ID"):
    payload["source_connection_id"] = os.environ["AP_SOURCE_ID"]
if os.environ.get("AP_TARGET_ID"):
    payload["ai_target_id"] = os.environ["AP_TARGET_ID"]
created = request("POST", "/api/v1/runs", payload)
run_id = created["id"]
print(f"AccessProof run: {run_id}")
for _ in range(600):
    run = request("GET", f"/api/v1/runs/{run_id}")
    outcome = run.get("outcome")
    if outcome:
        print(f"AccessProof outcome: {outcome}")
        print(f"Report: {BASE}/api/v1/reports/{run_id}.html")
        if outcome == "PASS":
            sys.exit(0)
        if outcome == "FAIL":
            sys.exit(1)
        if outcome in {"INCONCLUSIVE", "PRECONDITION_FAILURE"}:
            sys.exit(2 if os.environ.get("AP_INCONCLUSIVE_BLOCKS", "true").lower() == "true" else 0)
        sys.exit(3)
    time.sleep(2)
print("AccessProof run timed out waiting for control-plane result", file=sys.stderr)
sys.exit(3)
