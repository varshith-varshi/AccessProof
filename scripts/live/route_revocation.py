"""Route-level revocation evidence for revocation_trial.py --route (lab RAG only).

E2E-07  post-revocation denial on the REAL protected route: after the Guard's
        stable denial, the revoked document never reaches the model and the
        employee never receives its canary.
E2E-08  cached answer reuse denied: the unprotected (cached) baseline route is
        unreachable, identical protected questions are never served from a
        cache, and the answer Alice received BEFORE revocation is not returned
        to her after it.
E2E-09  in-flight revocation: while the revocation propagates, protected
        requests are issued back-to-back with the lab model paused ~20 s each
        (under the Gateway's 30 s model timeout). A request whose Layer 1 ran
        before the Guard acknowledged the revocation and whose Layer 2 ran
        after it shows the document in the model context; its answer must be
        withheld. Every straddling request is reported; none may release.

Only synthetic canary presence, hashes, HTTP statuses and timestamps are kept.
"""
from __future__ import annotations

import importlib.util
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("rag_e2e", HERE / "rag_e2e.py")
rag = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rag)

MODEL = "sharepoint-rag-lab-model-1"
QUESTION_FOR = {"finance_alice.txt": "finance"}
PAUSE_SECONDS = 20

_BASELINE = r'''
import json, sys, urllib.request, urllib.error
p = json.load(sys.stdin)
req = urllib.request.Request("http://127.0.0.1:8187/chat", data=json.dumps({"question": p["q"]}).encode(),
    headers={"Content-Type": "application/json"}, method="POST")
try:
    with urllib.request.urlopen(req, timeout=60) as r:
        print(json.dumps({"status": r.status, "body": json.loads(r.read())}))
except urllib.error.HTTPError as e:
    raw = e.read()
    try: body = json.loads(raw)
    except Exception: body = {"raw": raw[:200].decode("utf-8", "replace")}
    print(json.dumps({"status": e.code, "body": body}))
'''


HOLD = Path.home() / "Downloads/sharepoint-rag-lab/witness/ap-hold"


def _ask(token: str, question: str, *, pause: bool = False) -> dict:
    """``pause`` holds the model answer with the lab bridge's hold marker
    (connection stays healthy; freezing the container broke the Gateway's model
    connection and produced 503s before Layer 2)."""
    start, t_start = rag.witness_lines(), rag.now()
    release = None
    if pause:
        HOLD.write_text("hold")
        release = threading.Timer(PAUSE_SECONDS, lambda: HOLD.unlink(missing_ok=True))
        release.start()
    try:
        resp = rag.exec_in_rag(rag._CALL, {"q": rag.Q[question], "t": token})
    finally:
        if release is not None:
            release.join()
            HOLD.unlink(missing_ok=True)
    time.sleep(1)
    s = rag.summarize(resp, rag.witness_since(start))
    return {"started_at": t_start, "finished_at": rag.now(), **s}


def _released(doc: str, s: dict) -> bool:
    return doc in s["answer_canaries"] or doc in s["model_reply_documents"]


def judge_inflight(doc: str, requests: list[dict], phase: dict) -> dict:
    """Judge in-flight revocation against the trial's own timestamps.

    Before AccessProof detected the revocation (t2) the Guard legitimately
    still allows: a release then is propagation latency, measured by the
    trial, not an in-flight failure. FAIL = the document's content released
    in a response that finished after detection. PASS needs at least one
    straddling request (Layer 1 before t2, response after t2) that carried the
    document into the model context and whose answer was withheld.
    """
    t2 = phase.get("t2_accessproof_detected")
    ok = [r for r in requests if "error" not in r]
    if not t2:
        return {"requests": requests, "status": "NOT_OBSERVED", "reason": "revocation not detected in this phase"}
    after = [r for r in ok if r["finished_at"] > t2]
    leaked = [r for r in after if _released(doc, r)]
    straddling = [r for r in after if r["started_at"] < t2 and doc in r["model_context_documents"]]
    withheld = [r for r in straddling if r["http_status"] != 200 or not _released(doc, r)]
    before = [r for r in ok if r["finished_at"] <= t2 and _released(doc, r)]
    status = "FAIL" if leaked else ("PASS" if withheld else "NOT_OBSERVED")
    return {"requests": requests, "reference_t2_accessproof_detected": t2,
            "reference_t5_first_guard_denial": phase.get("t5_first_decision"),
            "released_before_detection_propagation_window": len(before),
            "straddling_requests": len(straddling), "straddling_withheld": len(withheld),
            "released_after_detection": len(leaked), "status": status}


class RouteProbe:
    def __init__(self, fetch_token, doc: str):
        self.fetch_token, self.doc = fetch_token, doc
        self.question = QUESTION_FOR[doc]
        self.results: dict = {}
        self._stop = threading.Event()
        self._inflight: list[dict] = []
        self._thread: threading.Thread | None = None

    def before_revoke(self) -> None:
        base = rag.exec_in_rag(_BASELINE, {"q": rag.Q[self.question]})
        first = _ask(self.fetch_token(), self.question)
        second = _ask(self.fetch_token(), self.question)
        ok = (base.get("status") not in (200,) and first["http_status"] == 200 and second["http_status"] == 200
              and first["cache_hit"] is False and second["cache_hit"] is False
              and self.doc in first["model_context_documents"] and second["model_calls"] == 1)
        self.results["E2E-08-pre"] = {"baseline_cached_route_status": base.get("status"),
                                      "baseline_cached_route_detail": (base.get("body") or {}).get("detail"),
                                      "protected_first": first, "protected_repeat": second,
                                      "pre_revocation_answer_sha256": first["answer_sha256"],
                                      "status": "PASS" if ok else "FAIL"}

    def start_inflight(self) -> None:
        def loop():
            while not self._stop.is_set():
                try:
                    self._inflight.append(_ask(self.fetch_token(), self.question, pause=True))
                except Exception as exc:  # recorded, never hidden
                    self._inflight.append({"error": type(exc).__name__, "at": rag.now()})
                    time.sleep(2)
        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop_inflight(self, phase: dict | None = None) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=120)
        HOLD.unlink(missing_ok=True)
        self.results["E2E-09"] = judge_inflight(self.doc, self._inflight, phase or {})

    def after_stable_denial(self) -> None:
        s = _ask(self.fetch_token(), self.question)
        ok7 = self.doc not in s["model_context_documents"] and not _released(self.doc, s)
        self.results["E2E-07"] = {"observed": s, "status": "PASS" if ok7 else "FAIL"}
        pre = self.results.get("E2E-08-pre", {})
        again = _ask(self.fetch_token(), self.question)
        ok8 = (pre.get("status") == "PASS" and not _released(self.doc, again) and again["cache_hit"] is not True
               and again["answer_sha256"] != pre.get("pre_revocation_answer_sha256"))
        self.results["E2E-08"] = {"post_revocation_repeat": again, "status": "PASS" if ok8 else "FAIL"}
