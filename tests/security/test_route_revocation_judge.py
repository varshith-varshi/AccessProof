"""E2E-09 judge: awareness starts at the earliest of notification / detection."""
import importlib.util
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location("route_revocation", Path("scripts/live/route_revocation.py"))
try:
    rr = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(rr)
except Exception:  # pragma: no cover - lab-only helper module imports
    pytest.skip("route_revocation helpers unavailable", allow_module_level=True)

DOC = "finance_alice.txt"


def req(start, end, status, ctx, reply):
    return {"started_at": f"2026-11-04T12:{start}+00:00", "finished_at": f"2026-11-04T12:{end}+00:00",
            "http_status": status, "model_context_documents": ctx, "model_reply_documents": reply,
            "answer_canaries": reply, "detail": None if status == 200 else "X"}


PHASE = {"t2n_notification_received": "2026-11-04T12:17:45.000000+00", "t2_accessproof_detected": "2026-11-04T12:18:05+00:00"}


def test_straddle_across_notification_withheld_passes():
    r = [req("17:14", "17:39", 200, [DOC], [DOC]), req("17:39", "18:02", 503, [DOC], [DOC]),
         req("18:02", "18:25", 200, [], [])]
    out = rr.judge_inflight(DOC, r, PHASE)
    assert out["status"] == "PASS" and out["straddling_withheld"] == 1 and out["released_after_detection"] == 0


def test_release_after_notification_is_a_leak():
    r = [req("17:39", "17:50", 200, [DOC], [DOC])]
    assert rr.judge_inflight(DOC, r, PHASE)["status"] == "FAIL"


def test_no_straddle_is_not_observed():
    r = [req("18:02", "18:25", 200, [], [])]
    assert rr.judge_inflight(DOC, r, PHASE)["status"] == "NOT_OBSERVED"


def test_without_notification_uses_detection():
    phase = {"t2_accessproof_detected": "2026-11-04T12:18:05+00:00"}
    r = [req("17:39", "18:02", 200, [DOC], [DOC])]   # finished before detection: propagation window
    out = rr.judge_inflight(DOC, r, phase)
    assert out["status"] == "NOT_OBSERVED" and out["released_before_detection_propagation_window"] == 1


def test_withheld_response_with_model_reply_is_not_a_leak_but_200_is():
    r = [req("17:39", "18:02", 503, [DOC], [DOC])]
    assert rr.judge_inflight(DOC, r, PHASE)["released_after_detection"] == 0
    r = [req("17:39", "18:02", 200, [DOC], [DOC])]
    assert rr.judge_inflight(DOC, r, PHASE)["status"] == "FAIL"
