#!/usr/bin/env python3
"""Live Layer 1 Guard matrix (lab Guard on 127.0.0.1:8080, synthetic lab files only).

    python scripts/live/layer1_matrix.py --out layer1.json

For Alice and Bob, asks the REAL Guard ``/guard/v1/filter-resources`` whether
each synthetic document may enter the model context, using that employee's
user-delegated RAG API access token (scope access_as_user). Negative controls:
the same employee's ID token and a tampered access token must be rejected
(401), proving the Guard enforces the required scope and the signature.
Stores decisions, ids and timestamps only; never tokens or content.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ei", HERE / "employee_identity.py")
ei = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ei)

GUARD = "http://127.0.0.1:8080/guard/v1/filter-resources"
APP = "sharepoint-rag-staging"
ORG = "48ee8c86-d4d8-4cde-b00b-bc779f965f4f"
SRC = "2fa9562b-b765-4098-bebf-222ea53ec667"
GUARD_CONTAINER = "accessproof-guard"
RAG_CONTAINER = "sharepoint-rag-lab-rag-1"
FIXTURE_STATE = Path.home() / ".config/accessproof/lab-fixtures.json"

import importlib.util as _ilu  # noqa: E402
_ps = _ilu.spec_from_file_location("_ap_profile", Path(__file__).resolve().parent / "_profile.py")
_pm = _ilu.module_from_spec(_ps)
_ps.loader.exec_module(_pm)
EXPECT = {
    "alice": {"finance_alice.txt": "ALLOW", "engineering_bob.txt": "DENY", "shared_control.txt": "ALLOW",
              "group_finance_alice.txt": "ALLOW", "inherited_finance_alice.txt": "ALLOW"},
    "bob": {"finance_alice.txt": "DENY", "engineering_bob.txt": "ALLOW", "shared_control.txt": "ALLOW",
            "group_finance_alice.txt": "DENY", "inherited_finance_alice.txt": "DENY"},
}

PROFILE = _pm.apply("layer1_matrix", globals())


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def indexed_versions() -> dict[str, str]:
    """Document versions exactly as the lab RAG indexed them (what a real RAG sends)."""
    code = ("import sqlite3,json;c=sqlite3.connect('file:/data/index.db?mode=ro',uri=True);"
            "print(json.dumps(dict(c.execute('select doc_id, max(version) from chunks group by doc_id').fetchall())))")
    out = subprocess.run(["docker", "exec", RAG_CONTAINER, "python", "-c", code],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


VERSIONS: dict[str, str] = {}
UNSET = object()


def ask(token: str, actor: str, resource_id: str, version: object = UNSET) -> tuple[int, dict]:
    ref = {"source_id": SRC, "resource_id": resource_id}
    v = VERSIONS.get(resource_id) if version is UNSET else version
    if v is not None:
        ref["content_version"] = v
    r = httpx.post(GUARD, timeout=20, headers={"Authorization": "Bearer " + token},
                   json={"application_id": APP, "request_id": f"l1-{actor}-{time.time_ns()}",
                         "resources": [ref]})
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    return r.status_code, body


def tamper(token: str) -> str:
    head, payload, sig = token.split(".")
    return ".".join([head, payload, ("A" if sig[0] != "A" else "B") + sig[1:]])


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", required=True)
    p.add_argument("--sockets", default=str(Path.home() / ".ap-id"))
    a = p.parse_args()
    with httpx.Client(timeout=30, trust_env=False) as h:
        _drive, items = ei.item_refs(h)
    fixtures = json.load(open(str(FIXTURE_STATE)))
    items["inherited_finance_alice.txt"] = fixtures["inherited_file_id"]
    VERSIONS.update(indexed_versions())
    rows, controls = [], []
    for actor, expected in EXPECT.items():
        sock = f"{a.sockets}/{actor}.sock"
        token = ei.fetch(sock, "api_token")
        for doc, want in expected.items():
            status, body = ask(token, actor, items[doc])
            allowed = {x.get("resource_id") for x in body.get("allowed", [])}
            got = ("ALLOW" if items[doc] in allowed else "DENY") if status == 200 else f"HTTP_{status}:{body.get('detail')}"
            rows.append({"actor": actor, "document": doc, "expected": want, "guard_decision": got,
                         "decision_id": body.get("decision_id"), "policy_version": body.get("policy_version"),
                         "authorization_revision": body.get("authorization_revision"), "pass": got == want, "at": now()})
            print(f"{actor:5s} {doc:28s} expected {want:5s} guard {got:5s} {'PASS' if got == want else 'FAIL'}")
        doc = next(d for d, w in expected.items() if w == "ALLOW")
        # Cached-chunk freshness controls: the same authorized document with an
        # older or absent content version must be refused (fail closed).
        for kind, version, reason in (("stale_content_version_denied", "\"{00000000-0000-0000-0000-000000000000},1\"",
                                       "SOURCE_CONTENT_VERSION_STALE"),
                                      ("missing_content_version_denied", None, "SOURCE_CONTENT_VERSION_REQUIRED")):
            status, body = ask(token, actor, items[doc], version)
            got = [d.get("reason") for d in body.get("denied", [])]
            ok = status == 200 and not body.get("allowed") and reason in got
            controls.append({"actor": actor, "control": kind, "http_status": status, "detail": got or body.get("detail"),
                             "pass": ok, "at": now()})
            print(f"{actor:5s} control {kind:28s} {got} {'PASS' if ok else 'FAIL'}")
        for kind, tok in (("id_token_rejected", ei.fetch(sock, "id_token")), ("tampered_signature_rejected", tamper(token))):
            status, body = ask(tok, actor, items[doc])
            ok = status == 401
            controls.append({"actor": actor, "control": kind, "http_status": status, "detail": body.get("detail"),
                             "pass": ok, "at": now()})
            print(f"{actor:5s} control {kind:28s} HTTP {status} {'PASS' if ok else 'FAIL'}")
    image = subprocess.run(["docker", "inspect", "-f", "{{.Config.Image}}", GUARD_CONTAINER],
                           capture_output=True, text=True).stdout.strip()
    out = {"schema": "accessproof.layer1_guard_matrix/v3", "organization_id": ORG, "source_id": SRC, "application_id": APP, "content_versions": "as indexed by the lab RAG (Graph eTag)", "guard_image": image, "generated_at": now(),
           "token": "Entra v2 user-delegated access token for the RAG API (scp=access_as_user); "
                    "identity via automatic directory_verified binding",
           "results": rows, "negative_controls": controls,
           "pass": all(r["pass"] for r in rows) and all(c["pass"] for c in controls)}
    Path(a.out).write_text(json.dumps(out, indent=1))
    print("PASS" if out["pass"] else "FAIL", f"{sum(r['pass'] for r in rows)}/{len(rows)} decisions,",
          f"{sum(c['pass'] for c in controls)}/{len(controls)} controls")
    return 0 if out["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
