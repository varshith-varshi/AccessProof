"""Lab-only Layer 1 witness: which synthetic canaries reach the model.

Records, per model request/response, ONLY: UTC time, sha256 of the request
body, which configured canary markers occur in the request (model context)
and in the model's reply. Never stores prompts, answers or tokens.
"""
from __future__ import annotations
import hashlib, json, os, threading
from datetime import datetime, timezone

_LOCK = threading.Lock()


def _markers() -> dict[str, str]:
    try:
        value = json.loads(os.environ.get("LAB_CONTEXT_WITNESS_MARKERS", "{}"))
    except ValueError:
        return {}
    return {str(k): str(v) for k, v in value.items() if isinstance(v, str) and len(v) >= 12}


def record(request_body: bytes, response_body: bytes | None, status: int) -> None:
    path = os.environ.get("LAB_CONTEXT_WITNESS_LOG", "")
    if not path:
        return
    markers = _markers()
    req = request_body.decode("utf-8", "replace")
    resp = (response_body or b"").decode("utf-8", "replace")
    row = {
        "at": datetime.now(timezone.utc).isoformat(),
        "request_sha256": hashlib.sha256(request_body).hexdigest(),
        "status": status,
        "context_markers": sorted(k for k, m in markers.items() if m in req),
        "reply_markers": sorted(k for k, m in markers.items() if m in resp),
    }
    with _LOCK, open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\n")
