"""Continuous trusted-ingestion evidence for a REMOTE RAG host.

    from accessproof_rag.evidence import EvidenceSubscriber
    sub = EvidenceSubscriber(gateway, source_id=..., tenant_id=..., application_id=...,
                             manifest_keys={"kid": "<b64url ed25519 pub>"},
                             attestation_keys={"kid": "<b64url ed25519 pub>"},
                             cache_path="/var/lib/rag/evidence.json")
    sub.start()                      # background refresh: interval + jitter + bounded retries
    chunks = sub.search(question)    # TrustedChunk list; raises EvidenceUnavailable when expired

Every fetched manifest is verified HERE (pinned keys, binding, monotonic seq,
every chunk attestation, expiry) before an atomic in-memory swap and an
atomic on-disk write. A restart reloads the cache and re-verifies it; expired
or invalid evidence is never used: the RAG fails closed until a refresh
succeeds. Nothing is extended locally. Needs ``pip install accessproof-rag[evidence]``.
"""
from __future__ import annotations

import base64
import json
import os
import random
import re
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._manifest import ManifestError, manifest_sha256, verify_manifest
from .client import AccessProofError, TrustedChunk


class EvidenceUnavailable(AccessProofError):
    """No currently valid trusted-ingestion evidence: answer nothing (fail closed)."""


def _keys(m: Mapping[str, str]) -> dict[str, Ed25519PublicKey]:
    return {k: Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))) for k, v in m.items()}


def _iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat() if ts else None


class EvidenceSubscriber:
    def __init__(self, gateway: Any, *, source_id: str, tenant_id: str, application_id: str,
                 manifest_keys: Mapping[str, str], attestation_keys: Mapping[str, str],
                 cache_path: str | None = None, interval_seconds: float = 300.0, jitter_fraction: float = 0.1,
                 max_retries: int = 3, backoff_seconds: float = 2.0, alert_window_seconds: float = 600.0,
                 clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep,
                 rng: random.Random | None = None) -> None:
        if not 10 <= interval_seconds <= 1500 or not 0 <= max_retries <= 10 or not 0 <= jitter_fraction <= 0.5:
            raise ValueError("invalid refresh policy")
        self.gateway, self.source_id, self.tenant_id, self.application_id = gateway, source_id, tenant_id, application_id
        self._manifest_keys, self._attestation_keys = _keys(manifest_keys), _keys(attestation_keys)
        self.cache_path = Path(cache_path) if cache_path else None
        self.interval, self.jitter, self.max_retries, self.backoff = interval_seconds, jitter_fraction, max_retries, backoff_seconds
        self.alert_window = alert_window_seconds
        self.clock, self.sleep, self.rng = clock, sleep, rng or random.Random()
        self._lock = threading.RLock()
        self._manifest: dict | None = None
        self._sha: str | None = None
        self._last_attempt = self._last_success = None
        self._failures, self._last_error = 0, None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._seq_floor = 0            # rollback floor survives an expired/rejected cache
        self._load_cache()

    # -------------------------------------------------------------- verification + state
    def _verify(self, manifest: dict) -> dict:
        with self._lock:
            min_seq = int(self._manifest["seq"]) if self._manifest else 0
            return verify_manifest(manifest, manifest_keys=self._manifest_keys, attestation_keys=self._attestation_keys,
                                   tenant_id=self.tenant_id, application_id=self.application_id, source_id=self.source_id,
                                   now=int(self.clock()), min_seq=min_seq, last_sha256=self._sha)

    def _install(self, manifest: dict, raw: bytes) -> None:
        with self._lock:                        # atomic swap: readers see old OR new, never partial
            self._manifest, self._sha = manifest, manifest_sha256(manifest)
        if self.cache_path is not None:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.cache_path.parent, prefix=".evidence.")
            with os.fdopen(fd, "wb") as fh:
                fh.write(raw)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.cache_path)

    def _load_cache(self) -> None:
        if self.cache_path is None or not self.cache_path.exists():
            return
        try:
            raw = self.cache_path.read_bytes()
            m = json.loads(raw)
            # Restart: the persisted manifest is re-verified like a fresh download.
            m = verify_manifest(m, manifest_keys=self._manifest_keys, attestation_keys=self._attestation_keys,
                                tenant_id=self.tenant_id, application_id=self.application_id, source_id=self.source_id,
                                now=int(self.clock()))
            with self._lock:
                self._manifest, self._sha = m, manifest_sha256(m)
        except (ManifestError, ValueError, KeyError, TypeError) as exc:
            self._last_error = f"CACHE_REJECTED:{exc}"
            # Keep the seq floor of a merely-expired cache so a rollback is still refused.
            try:
                seq_floor = int(json.loads(self.cache_path.read_bytes()).get("seq", 0))
            except Exception:
                seq_floor = 0
            self._seq_floor = seq_floor

    def refresh_once(self) -> dict:
        self._last_attempt = self.clock()
        error = "UNKNOWN"
        for attempt in range(self.max_retries + 1):
            try:
                raw = self.gateway.fetch_evidence(self.source_id)
                manifest = json.loads(raw)
                if self._manifest is None and int(manifest.get("seq", -1)) < self._seq_floor:
                    raise ManifestError("MANIFEST_ROLLBACK")
                with self._lock:
                    verified = self._verify(manifest)            # also re-checks an unchanged manifest's expiry
                    if manifest_sha256(manifest) != self._sha:
                        self._install(verified, raw)
                self._failures, self._last_success, self._last_error = 0, self.clock(), None
                return {"status": "OK", "seq": verified["seq"], "expires_at": verified["expires_at"], "attempts": attempt + 1}
            except (AccessProofError, ManifestError, ValueError, KeyError, TypeError) as exc:
                error = getattr(exc, "code", None) or str(exc) or type(exc).__name__
                if attempt < self.max_retries:
                    self.sleep(min(self.backoff * 2 ** attempt, 30.0) * (1 + self.rng.uniform(0, 0.5)))
        self._failures += 1
        self._last_error = error
        return {"status": "FAILED", "error": error, "consecutive_failures": self._failures}

    # -------------------------------------------------------------- use
    def current(self) -> dict:
        with self._lock:
            m = self._manifest
        if m is None:
            raise EvidenceUnavailable("EVIDENCE_NOT_AVAILABLE")
        if self.clock() >= m["expires_at"]:
            raise EvidenceUnavailable("EVIDENCE_EXPIRED")
        return m

    def chunks(self) -> list[TrustedChunk]:
        m = self.current()
        return [TrustedChunk(source_id=m["source_id"], resource_id=c["resource_id"], chunk_id=c["chunk_id"],
                             content=c["content"], content_version=c["content_version"],
                             content_attestation=c["content_attestation"]) for c in m["chunks"]]

    def search(self, question: str, limit: int = 5) -> list[TrustedChunk]:
        tokens = set(re.findall(r"[a-z0-9]{2,}", question.lower())[:20])
        scored = []
        for c in self.chunks():
            hit = len(tokens & set(re.findall(r"[a-z0-9]{2,}", c.content.lower())))
            if hit:
                scored.append((-hit, c.chunk_id, c))
        return [c for *_k, c in sorted(scored, key=lambda t: (t[0], t[1]))[:limit]]

    def health(self) -> dict:
        with self._lock:
            m = self._manifest
        now = self.clock()
        remaining = (m["expires_at"] - now) if m else None
        state = "NO_EVIDENCE" if m is None else "EXPIRED" if remaining <= 0 else "DEGRADED" if self._failures else "OK"
        return {"state": state, "seq": m["seq"] if m else None, "expires_at": _iso(m["expires_at"]) if m else None,
                "seconds_remaining": round(remaining, 1) if remaining is not None else None,
                "alert": bool(m is None or remaining <= self.alert_window),
                "last_attempt_at": _iso(self._last_attempt), "last_success_at": _iso(self._last_success),
                "consecutive_failures": self._failures, "last_error": self._last_error,
                "documents": len(m["documents"]) if m else 0, "chunks": len(m["chunks"]) if m else 0}

    # -------------------------------------------------------------- background loop
    def next_delay(self) -> float:
        delay = self.interval * (1 + self.rng.uniform(-self.jitter, self.jitter))
        with self._lock:
            m = self._manifest
        if m is not None:
            delay = min(delay, max(5.0, (m["expires_at"] - self.clock()) / 3))
        if self._failures:
            delay = min(delay, 15.0 * (1 + self.rng.uniform(0, 0.5)))      # recover quickly after an outage
        return max(2.0, delay)

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name="accessproof-evidence", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            self.refresh_once()
            self._stop.wait(self.next_delay())
