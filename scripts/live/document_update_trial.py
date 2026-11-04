#!/usr/bin/env python3
"""Live cached-chunk freshness trial (synthetic lab file only).

    python scripts/live/document_update_trial.py --out update.json [--execute]

Appends one synthetic line to shared_control.txt in SharePoint (its canary
string is preserved), then records, until the lab RAG has re-indexed:
  t0  document updated in SharePoint (new eTag)
  t1  Guard installed the new current version
  t2  lab RAG index holds the new version
Throughout, the REAL protected route is queried as Alice, and the Guard is
asked directly with the OLD version. Expected: once t1 passes, chunks still at
the old version never reach the model (stale cache refused, fail closed);
after t2 the document is served again at the new version.
Stores timestamps, decisions, versions and canary presence only.
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


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ei, fx, rag = _load("employee_identity"), _load("sharepoint_fixtures"), _load("rag_e2e")
DOC = "shared_control.txt"
SRC = "2fa9562b-b765-4098-bebf-222ea53ec667"
APP = "sharepoint-rag-staging"


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def guard_versions(item: str) -> list[str]:
    code = ("import sqlite3,json;c=sqlite3.connect('file:/var/lib/accessproof-guard/policy.db?mode=ro',uri=True);"
            f"r=c.execute(\"select versions_json from resource_versions where source_id='{SRC}' and resource_id='{item}'\").fetchone();"
            "print(r[0] if r else '[]')")
    return json.loads(subprocess.run(["docker", "exec", "accessproof-guard", "python", "-c", code],
                                     capture_output=True, text=True, check=True).stdout)


def index_version() -> str | None:
    code = ("import sqlite3;c=sqlite3.connect('file:/data/index.db?mode=ro',uri=True);"
            f"r=c.execute(\"select max(version) from chunks where name='{DOC}'\").fetchone();print(r[0] or '')")
    out = subprocess.run(["docker", "exec", rag.RAG, "python", "-c", code], capture_output=True, text=True).stdout.strip()
    return out or None


def guard_l1(token: str, item: str, version: str) -> str:
    r = httpx.post("http://127.0.0.1:8080/guard/v1/filter-resources", timeout=20,
                   headers={"Authorization": "Bearer " + token},
                   json={"application_id": APP, "request_id": f"upd-{time.time_ns()}",
                         "resources": [{"source_id": SRC, "resource_id": item, "content_version": version}]})
    body = r.json() if r.status_code == 200 else {}
    if r.status_code != 200:
        return f"HTTP_{r.status_code}"
    return "ALLOW" if body.get("allowed") else "DENY:" + ",".join(d.get("reason", "") for d in body.get("denied", []))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", required=True)
    p.add_argument("--execute", action="store_true")
    p.add_argument("--budget-seconds", type=int, default=1200)
    p.add_argument("--socket", default=str(Path.home() / ".ap-id/alice.sock"))
    a = p.parse_args()
    http = httpx.Client(timeout=30, trust_env=False)
    lab = fx.Lab(http)
    _drive, items = ei.item_refs(http)
    item = items[DOC]
    old_index = index_version()
    baseline = {"item_id": item, "guard_versions": guard_versions(item), "index_version": old_index}
    print(json.dumps({"baseline": baseline, "execute": a.execute}))
    if not a.execute:
        return 0
    if not old_index or old_index not in baseline["guard_versions"]:
        print("baseline: index version is not current in the Guard; refusing", file=sys.stderr)
        return 1
    original = http.get(f"{fx.G}/drives/{lab.drive}/items/{item}/content", headers=lab.h, follow_redirects=True)
    original.raise_for_status()
    text = original.text
    if rag.CANARY[DOC] not in text:
        print("canary missing from current content; refusing", file=sys.stderr)
        return 1
    result = {"schema": "accessproof.document_update_trial/v1", "document": DOC, "baseline": baseline,
              "samples": [], "t0_updated": None, "t1_guard_new_version": None, "t2_index_new_version": None}

    def save():
        Path(a.out).write_text(json.dumps(result, indent=1))
    t0 = time.monotonic()
    lab.upload(lab.folder, DOC, text.rstrip("\n") + f"\nSynthetic revision {now()} (freshness trial). No real data.\n")
    result["t0_updated"] = now()
    save()
    while time.monotonic() - t0 < a.budget_seconds:
        gv, iv = guard_versions(item), index_version()
        if result["t1_guard_new_version"] is None and old_index not in gv and gv:
            result["t1_guard_new_version"] = now()
        if result["t2_index_new_version"] is None and iv and iv != old_index:
            result["t2_index_new_version"] = now()
        token = ei.fetch(a.socket, rag.TOKEN_KIND)
        start = rag.witness_lines()
        resp = rag.exec_in_rag(rag._CALL, {"q": rag.Q["shared"], "t": token})
        time.sleep(1)
        s = rag.summarize(resp, rag.witness_since(start))
        result["samples"].append({
            "at": now(), "guard_versions": gv, "index_version": iv,
            "guard_layer1_old_version": guard_l1(token, item, old_index),
            "route_http_status": s["http_status"], "doc_in_model_context": DOC in s["model_context_documents"],
            "doc_canary_released": DOC in s["answer_canaries"],
        })
        save()
        if result["t2_index_new_version"] and result["samples"][-1]["doc_in_model_context"]:
            break
        time.sleep(15)
    samples = result["samples"]
    stale_window = [x for x in samples if old_index not in x["guard_versions"] and x["index_version"] == old_index]
    result["stale_window_samples"] = len(stale_window)
    result["stale_chunk_reached_model"] = any(x["doc_in_model_context"] for x in stale_window)
    result["old_version_refused_after_t1"] = all(x["guard_layer1_old_version"].startswith("DENY:SOURCE_CONTENT_VERSION_STALE")
                                                 for x in samples if old_index not in x["guard_versions"])
    result["served_again_after_reindex"] = bool(samples and samples[-1]["doc_in_model_context"]
                                                and samples[-1]["index_version"] != old_index)
    result["pass"] = (result["t1_guard_new_version"] is not None and not result["stale_chunk_reached_model"]
                      and result["old_version_refused_after_t1"] and result["served_again_after_reindex"])
    save()
    print(json.dumps({k: result[k] for k in ("t0_updated", "t1_guard_new_version", "t2_index_new_version",
                                             "stale_window_samples", "stale_chunk_reached_model",
                                             "old_version_refused_after_t1", "served_again_after_reindex", "pass")}))
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
