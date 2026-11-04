"""Remote (cross-host) exposure of the Gateway to customer RAG applications.

``ACCESSPROOF_GATEWAY_EXPOSURE``:
  * ``local`` (default): the validated reference topology. The Gateway is
    reachable only from the customer RAG's private Compose network and
    127.0.0.1; behaviour is unchanged.
  * ``remote``: a RAG application on ANOTHER host/OS/cloud calls the Gateway
    over the network. Then, and fail-closed at startup:
      - TLS is mandatory: the Gateway's own certificate
        (ACCESSPROOF_GATEWAY_TLS_CERT_FILE / _KEY_FILE, served by
        ``python -m apps.gateway.accessproof_gateway.serve``) or an explicitly
        declared terminating proxy (ACCESSPROOF_GATEWAY_TLS_TERMINATION=proxy).
      - Application (workload) authentication is mandatory on every protected
        route: ap-req-v1 HMAC request signatures (packages.rag_core.request_signing)
        with per-client secrets from ACCESSPROOF_GATEWAY_CLIENT_KEYS_JSON
        ({"client-id": "<base64url secret, >= 32 bytes>"}), single-use nonces,
        bounded clock skew, and a per-client rate limit.
      - The employee's own identity token is still required and verified by
        the Guard; signed source chunks are still verified (provenance).

Health endpoints stay unauthenticated and disclose only readiness.
"""
from __future__ import annotations

import base64
import json
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from packages.rag_core.request_signing import SignatureError, verify

PROTECTED_PREFIXES = ("/v1/",)


class RemoteAccessConfigError(RuntimeError):
    pass


@dataclass
class RemoteAccess:
    exposure: str = "local"
    secrets: dict[str, bytes] = field(default_factory=dict)
    max_skew: int = 300
    rate_per_minute: int = 600
    tls: str = "none"                       # "gateway" | "proxy" | "none"
    _nonces: "OrderedDict[str, float]" = field(default_factory=OrderedDict)
    _buckets: dict[str, list[float]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    max_nonces: int = 200_000

    @classmethod
    def from_env(cls) -> "RemoteAccess":
        exposure = os.getenv("ACCESSPROOF_GATEWAY_EXPOSURE", "local").strip().lower()
        if exposure not in {"local", "remote"}:
            raise RemoteAccessConfigError("ACCESSPROOF_GATEWAY_EXPOSURE must be local or remote")
        if exposure == "local":
            return cls()
        raw = os.getenv("ACCESSPROOF_GATEWAY_CLIENT_KEYS_JSON", "")
        try:
            decoded = json.loads(raw)
            if not isinstance(decoded, dict) or not decoded:
                raise ValueError
            secrets_by_client = {
                str(cid): base64.urlsafe_b64decode(str(v) + "=" * (-len(str(v)) % 4)) for cid, v in decoded.items()
            }
        except (ValueError, TypeError) as exc:
            raise RemoteAccessConfigError("remote exposure requires ACCESSPROOF_GATEWAY_CLIENT_KEYS_JSON") from exc
        if any(len(s) < 32 for s in secrets_by_client.values()):
            raise RemoteAccessConfigError("client secrets must be at least 32 bytes")
        cert, key = os.getenv("ACCESSPROOF_GATEWAY_TLS_CERT_FILE", ""), os.getenv("ACCESSPROOF_GATEWAY_TLS_KEY_FILE", "")
        termination = os.getenv("ACCESSPROOF_GATEWAY_TLS_TERMINATION", "").strip().lower()
        if cert and key:
            if not (os.path.isfile(cert) and os.path.isfile(key)):
                raise RemoteAccessConfigError("TLS certificate or key file missing")
            tls = "gateway"
        elif termination == "proxy":
            tls = "proxy"
        else:
            raise RemoteAccessConfigError("remote exposure requires TLS (gateway certificate or declared proxy termination)")
        skew = int(os.getenv("ACCESSPROOF_GATEWAY_CLIENT_MAX_SKEW_SECONDS", "300"))
        rate = int(os.getenv("ACCESSPROOF_GATEWAY_CLIENT_RATE_PER_MINUTE", "600"))
        if not 30 <= skew <= 900 or not 1 <= rate <= 100_000:
            raise RemoteAccessConfigError("invalid skew or rate limit")
        return cls(exposure="remote", secrets=secrets_by_client, max_skew=skew, rate_per_minute=rate, tls=tls)

    @property
    def remote(self) -> bool:
        return self.exposure == "remote"

    def check(self, *, method: str, path: str, headers: dict[str, str], body: bytes, now: float | None = None) -> str:
        """Return the authenticated client id or raise SignatureError (fail closed)."""
        now = time.time() if now is None else now
        client, nonce = verify(headers, method=method, path=path, body=body,
                               authorization=headers.get("authorization", ""),
                               secrets_by_client=self.secrets, now=int(now), max_skew=self.max_skew)
        with self._lock:
            horizon = now - 2 * self.max_skew
            while self._nonces and next(iter(self._nonces.values())) < horizon:
                self._nonces.popitem(last=False)
            key = f"{client}:{nonce}"
            if key in self._nonces:
                raise SignatureError("CLIENT_REQUEST_REPLAYED")
            if len(self._nonces) >= self.max_nonces:
                raise SignatureError("REPLAY_CACHE_FULL")   # fail closed under flood
            self._nonces[key] = now
            bucket = [t for t in self._buckets.get(client, []) if t > now - 60]
            if len(bucket) >= self.rate_per_minute:
                self._buckets[client] = bucket
                raise SignatureError("CLIENT_RATE_LIMITED")
            bucket.append(now)
            self._buckets[client] = bucket
        return client
