#!/usr/bin/env python3
"""Live multi-cycle soak of continuous trusted-ingestion refresh (lab, synthetic data).

Remote RAGs (LangChain + LlamaIndex, subscribe mode, isolated network) keep
answering through the remote TLS Gateway while the refresher re-attests every
~8 min against a 30-min TTL. Each minute: Alice/Bob finance questions alternate
across both routes; RAG evidence health and refresher health are recorded.
Scheduled live scenarios (real SharePoint / Guard / Gateway / containers):

  concurrent_refresh     3 extra refreshers race the daemon
  document_modified      shared_control.txt content changed in SharePoint, later restored
  document_deleted       delete_canary_alice.txt created, picked up, then deleted
  permission_revoked     Alice's finance grant removed DURING a refresh; restored after
  network_outage         LlamaIndex RAG cut from the Gateway for 10 min, then reconnected
  evidence_expiry        a third RAG cut off until its evidence EXPIRES (fail closed), then reconnected
  rag_restart_offline    LangChain RAG restarted while offline: resumes from verified cache
  tampered_manifest      a tampered manifest is placed in the publish dir: Gateway refuses to serve it
  tampered_cache         RAG cache tampered + restart: rejected, refetched
  cross_tenant           manifest requests for other tenant/source are refused

Writes JSON evidence only (statuses, ids, versions, hashes, canary presence).
"""
from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rrc_run = _load("remote_route_certification")
rag, rt, ei, fx = rrc_run.rag, rrc_run.rt, rrc_run.ei, _load("sharepoint_fixtures")
from packages.rag_core.request_signing import signed_headers  # noqa: E402

GW_DIR = Path.home() / ".ap-id/remote-gw"
ING = Path.home() / ".ap-id/ingestion"
LAB_PY = "/home/white-devil/NeuralMatrix-Paperclip/lab/accessproof/.venv/bin/python"
REFRESHER = HERE / "evidence_refresher_lab.py"
ROUTES = {"langchain": "http://127.0.0.1:18187", "llamaindex": "http://127.0.0.1:18188"}
CFG = json.loads((GW_DIR / "evidence-config.json").read_text())
PUB = ING / "published" / CFG["tenant_id"] / CFG["application_id"] / CFG["source_id"]
DEL_DOC = "delete_canary_alice.txt"
DEL_Q = "What does the synthetic deletion canary test document say? Quote its identifier."


def now():
    return datetime.now(timezone.utc).isoformat()


def sh(*cmd, inp=None, timeout=120):
    r = subprocess.run(list(cmd), input=inp, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()[-300:]


def ask(route_url, actor, question):
    rid = f"soak-{uuid.uuid4()}"
    start = rag.witness_lines()
    tok = rrc_run.token(actor)
    try:
        r = httpx.post(route_url + "/chat", json={"question": rag.Q.get(question, question)}, timeout=150, trust_env=False,
                       headers={"Authorization": "Bearer " + tok, "X-Request-Id": rid})
        st, body = r.status_code, (r.json() if r.headers.get("content-type", "").startswith("application/json") else {})
    except httpx.HTTPError as exc:
        st, body = None, {"detail": f"ROUTE_UNREACHABLE:{type(exc).__name__}"}
    time.sleep(1)
    s = rag.summarize({"status": st, "body": body}, rag.witness_since(start))
    s.update(request_id=rid, actor=actor, question=question, at=now(), detail=body.get("detail"))
    return s


def rag_health(route_url):
    try:
        r = httpx.get(route_url + "/health/evidence", timeout=10, trust_env=False)
        return r.json()
    except Exception as exc:
        return {"state": f"UNREACHABLE:{type(exc).__name__}"}


def exec_health(container):
    code = "import urllib.request,json\ntry:\n r=urllib.request.urlopen('http://127.0.0.1:8187/health/evidence',timeout=5);print(r.read().decode())\nexcept urllib.error.HTTPError as e:print(e.read().decode())"
    rc, out, _ = sh("docker", "exec", container, "python", "-c", code)
    return json.loads(out) if rc == 0 and out else {"state": "UNREACHABLE"}


def exec_chat(container, actor):
    code = ("import urllib.request,json,sys\np=json.load(sys.stdin)\nreq=urllib.request.Request('http://127.0.0.1:8187/chat',data=json.dumps({'question':p['q']}).encode(),"
            "headers={'Authorization':'Bearer '+p['t'],'Content-Type':'application/json'},method='POST')\n"
            "try:\n r=urllib.request.urlopen(req,timeout=120);print(json.dumps({'status':r.status,'detail':None}))\n"
            "except urllib.error.HTTPError as e:print(json.dumps({'status':e.code,'detail':json.loads(e.read()).get('detail')}))")
    rc, out, _ = sh("docker", "exec", "-i", container, "python", "-c", code,
                    inp=json.dumps({"q": rag.Q["shared"], "t": rrc_run.token(actor)}), timeout=180)
    return json.loads(out) if rc == 0 and out else {"status": None, "detail": "EXEC_FAILED"}


def refresher_health():
    try:
        return json.loads((ING / "health.json").read_text())
    except Exception:
        return {}


def published():
    try:
        m = json.loads((PUB / "current.json").read_bytes())
        return {"seq": m["seq"], "expires_at": m["expires_at"],
                "documents": {d["resource_id"]: d["content_version"] for d in m["documents"]}}
    except Exception as exc:
        return {"error": type(exc).__name__}


def cache_versions(name):
    try:
        m = json.loads((GW_DIR / "rag-cache" / name / "evidence.json").read_bytes())
        return {"seq": m["seq"], "documents": {d["resource_id"]: d["content_version"] for d in m["documents"]}}
    except Exception as exc:
        return {"error": type(exc).__name__}


def refresh_once():
    return sh(LAB_PY, str(REFRESHER), "--once", "--interval", "480", timeout=180)[0]


def wait_until(pred, timeout, step=10):
    t0 = time.time()
    while time.time() - t0 < timeout:
        v = pred()
        if v:
            return v
        time.sleep(step)
    return None


def certifier_manifest_request(source_id):
    secret = base64.urlsafe_b64decode((GW_DIR / "client-ap-route-certifier.secret").read_text().strip() + "==")
    body = json.dumps({"source_id": source_id}).encode()
    h = signed_headers("ap-route-certifier", secret, "POST", "/v1/evidence/manifest", body, "")
    return _tls_post("/v1/evidence/manifest", body, h)


def _tls_post(path, body, headers):
    import socket
    import ssl
    ctx = ssl.create_default_context(cafile=str(GW_DIR / "ca.pem"))
    with ctx.wrap_socket(socket.create_connection(("127.0.0.1", 8443), timeout=30), server_hostname="ap-gateway.lab.internal") as tls:
        req = (f"POST {path} HTTP/1.1\r\nHost: ap-gateway.lab.internal\r\nContent-Type: application/json\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n").encode() + body
        tls.sendall(req)
        resp = b""
        while chunk := tls.recv(65536):
            resp += chunk
    head, _, payload = resp.partition(b"\r\n\r\n")
    try:
        detail = json.loads(payload).get("detail")
    except Exception:
        detail = None
    return {"status": int(head.split(b" ")[1]), "detail": detail}


# ------------------------------------------------------------------------------ scenarios
def sc_concurrent(log):
    before = published().get("seq")
    threads = [threading.Thread(target=refresh_once) for _ in range(3)]
    [t.start() for t in threads]; [t.join() for t in threads]
    hist = sorted(PUB.glob("seq-*.json"))
    seqs = [json.loads(p.read_bytes())["seq"] for p in hist]
    tmp = list(PUB.glob(".*.tmp"))
    after = published().get("seq")
    ok = after >= before + 3 and seqs == list(range(seqs[0], seqs[0] + len(seqs))) and not tmp
    log({"scenario": "concurrent_refresh", "seq_before": before, "seq_after": after, "history": seqs, "tmp_files": len(tmp), "pass": ok})


def sc_modify(log, state):
    http = httpx.Client(timeout=30, trust_env=False)
    lab = fx.Lab(http)
    _d, items = ei.item_refs(http)
    item = items["shared_control.txt"]
    orig = http.get(f"{fx.G}/drives/{lab.drive}/items/{item}/content", headers=lab.h, follow_redirects=True).text
    old_ver = published()["documents"].get(item)
    state["shared_original"] = orig
    lab.upload(lab.folder, "shared_control.txt", orig + "\nSynthetic revision line added by the evidence-refresh soak.\n")
    t0 = now()
    refresh_once()                                   # refresh cycle picks it up (no need to wait for the timer)
    new_ver = published()["documents"].get(item)
    picked = {n: wait_until(lambda n=n: (cache_versions(n).get("documents", {}).get(item) == new_ver) or None, 400) for n in ROUTES}
    a = ask(ROUTES["langchain"], "alice", "shared")
    log({"scenario": "document_modified", "item": item, "t0_modified": t0, "old_version": old_ver, "new_version": new_ver,
         "published_changed": new_ver != old_ver, "remote_rags_have_new_version": {k: bool(v) for k, v in picked.items()},
         "alice_shared_after": {k: a[k] for k in ("http_status", "model_context_documents", "answer_canaries")},
         "pass": new_ver != old_ver and all(picked.values()) and a["http_status"] == 200
         and "shared_control.txt" in a["model_context_documents"]})
    lab.upload(lab.folder, "shared_control.txt", orig)
    refresh_once()
    log({"scenario": "document_restored", "version": published()["documents"].get(item)})


def sc_delete(log):
    http = httpx.Client(timeout=30, trust_env=False)
    lab = fx.Lab(http)
    st = fx._state()
    body = "ACCESSPROOF_SYNTHETIC_DELETE_CANARY_20261103_D17 synthetic deletion canary test document for Alice.\n"
    item = lab.upload(lab.folder, DEL_DOC, body)
    lab.invite(item, st.get("alice_oid") or rt.Trial("A", rrc_run.SOCK["alice"]).alice_oid)
    lab.strip_site_groups(item)
    refresh_once()
    added = item in published()["documents"]
    seen = {n: bool(wait_until(lambda n=n: (item in cache_versions(n).get("documents", {})) or None, 400)) for n in ROUTES}
    http.delete(f"{fx.G}/drives/{lab.drive}/items/{item}", headers=lab.h).raise_for_status()
    t_del = now()
    refresh_once()
    gone_pub = item not in published()["documents"]
    gone = {n: bool(wait_until(lambda n=n: (item not in cache_versions(n).get("documents", {}) and
                                            "error" not in cache_versions(n)) or None, 400)) for n in ROUTES}
    a = ask(ROUTES["llamaindex"], "alice", DEL_Q)
    log({"scenario": "document_deleted", "item": item, "added_to_manifest": added, "remote_rags_saw_it": seen,
         "deleted_at": t_del, "removed_from_manifest": gone_pub, "removed_from_remote_rags": gone,
         "alice_after_delete": {k: a[k] for k in ("http_status", "model_context_documents", "answer_canaries")},
         "pass": added and all(seen.values()) and gone_pub and all(gone.values())
         and DEL_DOC not in a["model_context_documents"]})


def sc_revoke(log):
    trial = rt.Trial("A", rrc_run.SOCK["alice"])
    item = trial.item_id()
    rec = None
    try:
        rec = trial.revoke()
        refresh_once()                             # a refresh cycle runs while the revocation propagates
        pub = published()
        stable = wait_until(lambda: all(rt.guard_decision(rrc_run.token("alice"), item) == "DENY" for _ in range(2)) or None, 300, 10)
        after = [ask(ROUTES[n], "alice", "finance") for n in ROUTES]
        refresh_once()
        h = refresher_health()
        log({"scenario": "permission_revoked_during_refresh", "revoked_at": rec["at"],
             "finance_still_in_manifest_as_provenance": item in pub["documents"],
             "refresher_permissions_changed": h.get("last_changes", {}).get("permissions_changed"),
             "guard_stable_deny": bool(stable),
             "alice_after": [{k: s[k] for k in ("http_status", "model_context_documents", "answer_canaries", "request_id")} for s in after],
             "pass": bool(stable) and all("finance_alice.txt" not in s["model_context_documents"]
                                          and "finance_alice.txt" not in s["answer_canaries"] for s in after)})
    finally:
        trial.restore()
    ok = wait_until(lambda: rt.guard_decision(rrc_run.token("alice"), item) == "ALLOW" or None, 400, 10)
    log({"scenario": "permission_restored", "guard_allows_again": bool(ok)})


def sc_tampered_manifest(log):
    cur = PUB / "current.json"
    good = cur.read_bytes()
    m = json.loads(good)
    m["chunks"][0]["content"] += " TAMPERED"
    cur.write_bytes(json.dumps(m).encode())
    served = certifier_manifest_request(CFG["source_id"])
    time.sleep(5)
    rag_states = {n: rag_health(u) for n, u in ROUTES.items()}
    cur.write_bytes(good)                              # put the genuine manifest back, then a fresh cycle
    refresh_once()
    log({"scenario": "tampered_manifest", "gateway_response": served,
         "remote_rags_kept_valid_evidence": {n: h.get("state") for n, h in rag_states.items()},
         "pass": served["status"] == 503 and all(h.get("state") in ("OK", "DEGRADED") for h in rag_states.values())})


def sc_tampered_cache(log):
    p = GW_DIR / "rag-cache/langchain/evidence.json"
    m = json.loads(p.read_bytes())
    m["chunks"][0]["content"] += " INJECTED"
    p.write_text(json.dumps(m))
    sh("docker", "network", "disconnect", "ap-remote-edge", "ap-remote-rag-langchain")
    sh("docker", "restart", "ap-remote-rag-langchain")
    time.sleep(6)
    offline = exec_health("ap-remote-rag-langchain")
    sh("docker", "network", "connect", "ap-remote-edge", "ap-remote-rag-langchain")
    recovered = wait_until(lambda: (exec_health("ap-remote-rag-langchain").get("state") == "OK") or None, 120, 5)
    log({"scenario": "tampered_cache_restart", "offline_state": offline.get("state"), "offline_error": offline.get("last_error"),
         "recovered_after_reconnect": bool(recovered),
         "pass": offline.get("state") in ("NO_EVIDENCE",) and bool(recovered)})


def sc_restart_offline(log):
    sh("docker", "network", "disconnect", "ap-remote-edge", "ap-remote-rag-langchain")
    sh("docker", "restart", "ap-remote-rag-langchain")
    time.sleep(6)
    h = exec_health("ap-remote-rag-langchain")
    sh("docker", "network", "connect", "ap-remote-edge", "ap-remote-rag-langchain")
    time.sleep(5)
    a = ask(ROUTES["langchain"], "alice", "shared")
    log({"scenario": "rag_restart_offline", "state_after_offline_restart": h.get("state"), "seq": h.get("seq"),
         "served_after_reconnect": a["http_status"],
         "pass": h.get("state") in ("OK", "DEGRADED") and h.get("seq") is not None and a["http_status"] == 200})


def sc_cross_tenant(log):
    other = certifier_manifest_request(str(uuid.uuid4()))
    traversal = certifier_manifest_request("../" + CFG["source_id"])
    own = certifier_manifest_request(CFG["source_id"])
    log({"scenario": "cross_tenant", "other_source": other, "path_traversal": traversal, "own_source_status": own["status"],
         "pass": other["status"] == 404 and traversal["status"] == 400 and own["status"] == 200})


# ------------------------------------------------------------------------------ main loop
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--minutes", type=float, default=100)
    p.add_argument("--out", required=True)
    a = p.parse_args()
    out = {"schema": "accessproof.evidence-refresh-soak/v1", "started_at": now(), "samples": [], "scenarios": [],
           "expiry_probe": []}
    state = {}

    def save():
        Path(a.out).write_text(json.dumps(out, indent=1, default=str))

    def log(ev):
        ev["at"] = now()
        out["scenarios"].append(ev)
        print(json.dumps({k: ev[k] for k in ("scenario", "pass", "at") if k in ev}), flush=True)
        save()

    schedule = {5: lambda: sc_concurrent(log), 8: lambda: sc_modify(log, state), 16: lambda: sc_delete(log),
                24: lambda: sc_revoke(log), 36: lambda: sc_tampered_manifest(log), 40: lambda: sc_restart_offline(log),
                46: lambda: sc_cross_tenant(log), 80: lambda: sc_tampered_cache(log)}
    outage = {"start": 50, "end": 60, "cut": False}
    expiry = {"cut_at": 12, "reconnect_after_expired_min": 5, "cut": False, "expired_seen": None, "restored": False}
    t0 = time.time()
    i = 0
    while (time.time() - t0) / 60 < a.minutes:
        minute = (time.time() - t0) / 60
        for m in [k for k in sorted(schedule) if k <= minute]:
            try:
                schedule.pop(m)()
            except Exception as exc:                          # recorded, never hidden
                log({"scenario": f"error_at_minute_{m}", "error": f"{type(exc).__name__}: {str(exc)[:200]}", "pass": False})
        # network outage window for the LlamaIndex RAG
        if not outage["cut"] and minute >= outage["start"]:
            sh("docker", "network", "disconnect", "ap-remote-edge", "ap-remote-rag-llamaindex"); outage["cut"] = now()
        if outage["cut"] and not outage.get("restored") and minute >= outage["end"]:
            during = exec_health("ap-remote-rag-llamaindex")
            sh("docker", "network", "connect", "ap-remote-edge", "ap-remote-rag-llamaindex"); outage["restored"] = now()
            rec = wait_until(lambda: (exec_health("ap-remote-rag-llamaindex").get("consecutive_failures") == 0
                                      and exec_health("ap-remote-rag-llamaindex").get("state") == "OK") or None, 180, 5)
            log({"scenario": "network_outage_and_recovery", "cut_at": outage["cut"], "reconnected_at": outage["restored"],
                 "state_during_outage": during.get("state"), "failures_during_outage": during.get("consecutive_failures"),
                 "recovered": bool(rec), "pass": during.get("state") == "DEGRADED" and bool(rec)})
        # evidence expiry probe RAG
        if not expiry["cut"] and minute >= expiry["cut_at"]:
            sh("docker", "network", "disconnect", "ap-remote-edge", "ap-remote-rag-expiry"); expiry["cut"] = now()
        if expiry["cut"] and not expiry["restored"]:
            h = exec_health("ap-remote-rag-expiry")
            c = exec_chat("ap-remote-rag-expiry", "alice")
            out["expiry_probe"].append({"at": now(), "state": h.get("state"), "seconds_remaining": h.get("seconds_remaining"),
                                        "chat_status": c["status"], "chat_detail": c["detail"]})
            if h.get("state") == "EXPIRED" and not expiry["expired_seen"]:
                expiry["expired_seen"] = time.time()
            if expiry["expired_seen"] and time.time() - expiry["expired_seen"] > expiry["reconnect_after_expired_min"] * 60:
                sh("docker", "network", "connect", "ap-remote-edge", "ap-remote-rag-expiry")
                rec = wait_until(lambda: (exec_health("ap-remote-rag-expiry").get("state") == "OK") or None, 180, 5)
                c2 = exec_chat("ap-remote-rag-expiry", "alice") if rec else None
                probe = out["expiry_probe"]
                expired = [x for x in probe if x["state"] == "EXPIRED"]
                log({"scenario": "evidence_expiry_fail_closed_and_recovery", "cut_at": expiry["cut"],
                     "first_expired_at": expired[0]["at"] if expired else None,
                     "chat_while_expired": sorted({(x["chat_status"], x["chat_detail"]) for x in expired}),
                     "recovered": bool(rec), "chat_after_recovery": c2,
                     "pass": bool(expired) and all(x["chat_status"] == 503 and x["chat_detail"] == "EVIDENCE_EXPIRED" for x in expired)
                     and bool(rec) and c2 and c2["status"] == 200})
                expiry["restored"] = True
        # regular sample: alternate actor/route
        route = "langchain" if i % 2 == 0 else "llamaindex"
        if route == "llamaindex" and outage["cut"] and not outage.get("restored"):
            route = "langchain"
        actor = "alice" if (i // 2) % 2 == 0 else "bob"
        s = ask(ROUTES[route], actor, "finance")
        out["samples"].append({"route": route, **{k: s[k] for k in ("at", "actor", "http_status", "detail", "gateway_decision_id",
                                                                     "model_context_documents", "answer_canaries", "request_id")},
                               "rag_evidence": {n: {k: rag_health(u).get(k) for k in ("state", "seq", "seconds_remaining")}
                                                for n, u in ROUTES.items()},
                               "refresher": {k: refresher_health().get(k) for k in ("state", "seq", "seconds_remaining",
                                                                                     "consecutive_failures", "last_success_at")}})
        save()
        i += 1
        time.sleep(max(0, 60 - (time.time() - t0) % 60))
    out["finished_at"] = now()
    save()


if __name__ == "__main__":
    main()
