"""Continuous trusted-ingestion refresh (runs ONLY in the trusted-ingestion environment).

Each cycle:
  1. The source adapter re-reads the source NOW (e.g. SharePoint via Graph) and
     returns the current documents with chunks attested in this cycle (the
     ingestion signing key never leaves this environment). Deleted documents
     are simply absent; changed documents carry their new version.
  2. A new signed manifest is built (``evidence_manifest.build_manifest``),
     which refuses unverifiable, mismatched, over-long-TTL or nearly-expired
     attestations, and is published ATOMICALLY (temp file, fsync, rename, dir
     fsync) under an exclusive lock with a strictly increasing ``seq``.
  3. Changes against the previous manifest (added / updated / deleted /
     permission fingerprint changed) are recorded; health is written.

Failure handling: bounded retries with exponential backoff and jitter inside a
cycle; then the next cycle. Nothing is ever re-signed or extended on failure:
the last good manifest keeps its original expiry and remote RAGs fail closed
when it passes. The next cycle is pulled forward so it runs before expiry.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import random
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .evidence_manifest import ManifestError, build_manifest, iso, manifest_sha256

SourceAdapter = Callable[[], Mapping[str, Any]]


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)
    dfd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


class EvidencePublisher:
    """``<root>/<tenant>/<application>/<source>/current.json`` (+ bounded history)."""

    def __init__(self, root: str | Path, tenant_id: str, application_id: str, source_id: str, keep: int = 5) -> None:
        for part in (tenant_id, application_id, source_id):
            if not part or "/" in part or part in {".", ".."}:
                raise ValueError("invalid binding component")
        self.dir = Path(root) / tenant_id / application_id / source_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.current = self.dir / "current.json"
        self.keep = keep

    def read_current(self) -> dict | None:
        try:
            return json.loads(self.current.read_bytes())
        except FileNotFoundError:
            return None

    def publish(self, build: Callable[[int, str], dict]) -> dict:
        """Exclusive lock -> build(seq, previous_sha256) -> atomic replace."""
        with open(self.dir / ".publish.lock", "a+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                prev = self.read_current()
                seq = int(prev["seq"]) + 1 if prev else 1
                prev_sha = manifest_sha256(prev) if prev else "0" * 64
                manifest = build(seq, prev_sha)
                raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
                atomic_write(self.dir / f"seq-{seq:012d}.json", raw)
                atomic_write(self.current, raw)
                for old in sorted(self.dir.glob("seq-*.json"))[:-self.keep]:
                    old.unlink(missing_ok=True)
                return manifest
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


@dataclass
class RefreshPolicy:
    interval_seconds: float = 600.0
    jitter_fraction: float = 0.1
    max_retries: int = 3
    backoff_seconds: float = 5.0
    max_backoff_seconds: float = 60.0
    alert_window_seconds: float = 600.0
    safety_margin_seconds: float = 300.0
    attestation_ttl_seconds: int = 1800

    def __post_init__(self) -> None:
        if not (30 <= self.interval_seconds < self.attestation_ttl_seconds):
            raise ValueError("refresh interval must be >= 30 s and shorter than the attestation TTL")
        if not (0 <= self.jitter_fraction <= 0.5) or not (0 <= self.max_retries <= 10):
            raise ValueError("invalid jitter or retry bound")


@dataclass
class EvidenceRefresher:
    adapter: SourceAdapter
    publisher: EvidencePublisher
    tenant_id: str
    application_id: str
    source_id: str
    attestation_keys: Mapping[str, Ed25519PublicKey]
    manifest_key: Ed25519PrivateKey
    manifest_key_id: str
    policy: RefreshPolicy = field(default_factory=RefreshPolicy)
    clock: Callable[[], float] = time.time
    sleep: Callable[[float], None] = time.sleep
    rng: random.Random = field(default_factory=random.Random)
    health_path: Path | None = None
    on_event: Callable[[dict], None] | None = None
    _consecutive_failures: int = 0
    _last_attempt: float | None = None
    _last_success: float | None = None
    _last_error: str | None = None
    _last_changes: dict = field(default_factory=dict)
    _permissions: dict = field(default_factory=dict)

    # ------------------------------------------------------------------ one cycle
    def _attempt(self) -> dict:
        snapshot = self.adapter()
        docs, chunks = list(snapshot["documents"]), list(snapshot["chunks"])
        prev = self.publisher.read_current()
        now = int(self.clock())

        def build(seq: int, prev_sha: str) -> dict:
            return build_manifest(tenant_id=self.tenant_id, application_id=self.application_id, source_id=self.source_id,
                                  seq=seq, documents=docs, chunks=chunks, attestation_keys=self.attestation_keys,
                                  manifest_key=self.manifest_key, manifest_key_id=self.manifest_key_id,
                                  previous_sha256=prev_sha, now=now, max_ttl=self.policy.attestation_ttl_seconds)
        manifest = self.publisher.publish(build)
        before = {d["resource_id"]: d["content_version"] for d in (prev or {}).get("documents", [])}
        after = {d["resource_id"]: d["content_version"] for d in manifest["documents"]}
        perms = dict(snapshot.get("permissions") or {})
        changes = {"added": sorted(set(after) - set(before)), "deleted": sorted(set(before) - set(after)),
                   "updated": sorted(r for r in set(after) & set(before) if after[r] != before[r]),
                   "permissions_changed": sorted(r for r in perms if r in self._permissions and perms[r] != self._permissions[r]),
                   "permissions_observable": snapshot.get("permissions") is not None}
        self._permissions = perms
        return {"manifest": manifest, "changes": changes}

    def refresh_once(self) -> dict:
        self._last_attempt = self.clock()
        error = None
        for attempt in range(self.policy.max_retries + 1):
            try:
                out = self._attempt()
            except Exception as exc:          # recorded, never hidden, never "extended"
                error = f"{type(exc).__name__}:{exc}" if isinstance(exc, ManifestError) else type(exc).__name__
                if attempt < self.policy.max_retries:
                    base = min(self.policy.backoff_seconds * (2 ** attempt), self.policy.max_backoff_seconds)
                    self.sleep(base * (1 + self.rng.uniform(0, 0.5)))
                continue
            m = out["manifest"]
            self._consecutive_failures, self._last_success, self._last_error = 0, self.clock(), None
            self._last_changes = out["changes"]
            event = {"event": "EVIDENCE_REFRESHED", "seq": m["seq"], "expires_at": iso(m["expires_at"]),
                     "documents": len(m["documents"]), "chunks": len(m["chunks"]), "attempts": attempt + 1,
                     **{k: v for k, v in out["changes"].items()}}
            self._emit(event)
            self.write_health()
            return event
        self._consecutive_failures += 1
        self._last_error = error
        self._emit({"event": "EVIDENCE_REFRESH_FAILED", "error": error, "consecutive_failures": self._consecutive_failures})
        self.write_health()
        return {"event": "EVIDENCE_REFRESH_FAILED", "error": error}

    # ------------------------------------------------------------------ scheduling + health
    def next_delay(self) -> float:
        p = self.policy
        delay = p.interval_seconds * (1 + self.rng.uniform(-p.jitter_fraction, p.jitter_fraction))
        cur = self.publisher.read_current()
        if cur:
            # Always try again well before the published evidence expires.
            delay = min(delay, max(15.0, cur["expires_at"] - self.clock() - p.safety_margin_seconds))
        if self._consecutive_failures:
            delay = min(delay, min(p.max_backoff_seconds * 2, 120.0) * (1 + self.rng.uniform(0, 0.25)))
        return max(5.0, delay)

    def run_forever(self, stop: threading.Event) -> None:
        while not stop.is_set():
            self.refresh_once()
            stop.wait(self.next_delay())

    def health(self) -> dict:
        cur = self.publisher.read_current()
        now = self.clock()
        remaining = (cur["expires_at"] - now) if cur else None
        state = ("NO_EVIDENCE" if cur is None else "EXPIRED" if remaining <= 0
                 else "DEGRADED" if self._consecutive_failures else "OK")
        return {"state": state, "tenant_id": self.tenant_id, "application_id": self.application_id,
                "source_id": self.source_id, "seq": cur["seq"] if cur else None,
                "expires_at": iso(cur["expires_at"]) if cur else None,
                "seconds_remaining": round(remaining, 1) if remaining is not None else None,
                "alert": bool(cur is None or remaining <= self.policy.alert_window_seconds),
                "last_attempt_at": iso(int(self._last_attempt)) if self._last_attempt else None,
                "last_success_at": iso(int(self._last_success)) if self._last_success else None,
                "consecutive_failures": self._consecutive_failures, "last_error": self._last_error,
                "last_changes": self._last_changes,
                "manifest_sha256": manifest_sha256(cur) if cur else None}

    def write_health(self) -> None:
        if self.health_path is not None:
            atomic_write(self.health_path, json.dumps(self.health(), indent=1).encode())

    def _emit(self, event: dict) -> None:
        if self.on_event is not None:
            self.on_event({"at": iso(int(self.clock())), **event})


def permissions_fingerprint(permissions: list[dict]) -> str:
    """Stable digest of an item's permission set (ids, roles, grantees): change detection only."""
    norm = sorted(json.dumps({"id": p.get("id"), "roles": sorted(p.get("roles") or []),
                              "to": sorted(json.dumps(g, sort_keys=True) for g in
                                           (p.get("grantedToIdentitiesV2") or p.get("grantedToIdentities") or
                                            ([p.get("grantedToV2")] if p.get("grantedToV2") else []) or
                                            ([p.get("grantedTo")] if p.get("grantedTo") else [])))},
                             sort_keys=True) for p in permissions)
    return hashlib.sha256("\n".join(norm).encode()).hexdigest()
