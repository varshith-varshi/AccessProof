"""Authenticated Gateway heartbeat to the AccessProof control plane (D-02).

The Gateway reports (a) that this exact installation is running and (b) its
own ``/health/ready`` result. The control plane timestamps receipt with its own
clock and rejects replayed sequences. Missing heartbeats become DISCONNECTED.
A heartbeat never enables or certifies Protect.
"""
from __future__ import annotations

import os
import re
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

GATEWAY_VERSION = os.getenv("ACCESSPROOF_GATEWAY_VERSION", "gateway-v1")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class PresenceSettings:
    control_plane_url: str
    organization_id: str
    installation_id: str
    credential: str
    application_id: str
    route_sha256: str
    interval_seconds: float = 10.0

    def __post_init__(self) -> None:
        parsed = urlsplit(self.control_plane_url)
        local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if (parsed.scheme not in {"https", "http"} or not parsed.hostname
                or parsed.username or parsed.password
                or (parsed.scheme == "http" and not local)):
            # The credential must never travel in plaintext off-host.
            raise ValueError("Gateway presence requires an HTTPS control plane URL")
        if not (32 <= len(self.credential) <= 512) or not _DIGEST.fullmatch(self.route_sha256):
            raise ValueError("Gateway presence credential or route digest invalid")
        if not 2.0 <= self.interval_seconds <= 60.0:
            raise ValueError("Gateway presence interval unsafe")

    @classmethod
    def from_env(cls) -> "PresenceSettings | None":
        names = {
            "control_plane_url": "ACCESSPROOF_GATEWAY_PRESENCE_CONTROL_PLANE_URL",
            "organization_id": "ACCESSPROOF_GATEWAY_PRESENCE_ORGANIZATION_ID",
            "installation_id": "ACCESSPROOF_GATEWAY_PRESENCE_INSTALLATION_ID",
            "credential": "ACCESSPROOF_GATEWAY_PRESENCE_CREDENTIAL",
            "route_sha256": "ACCESSPROOF_GATEWAY_PRESENCE_ROUTE_SHA256",
        }
        values = {key: os.getenv(env, "") for key, env in names.items()}
        if not any(values.values()):
            return None  # Legacy installation: control plane reports UNKNOWN.
        if not all(values.values()):
            raise ValueError("Gateway presence configuration incomplete")
        return cls(
            application_id=os.getenv("ACCESSPROOF_GATEWAY_APPLICATION_ID", ""),
            interval_seconds=float(os.getenv("ACCESSPROOF_GATEWAY_PRESENCE_INTERVAL_SECONDS", "10")),
            **values,
        )


class PresenceReporter:
    def __init__(self, settings: PresenceSettings, client: httpx.Client | None = None) -> None:
        self.settings = settings
        self.client = client or httpx.Client(timeout=5, follow_redirects=False, trust_env=False)
        self._owns_client = client is None
        self._last_sequence = 0
        self._lock = threading.Lock()

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    def _next_sequence(self) -> int:
        # Wall-clock milliseconds survive restarts of a read-only container
        # without local state; strictly increasing within the process.
        with self._lock:
            self._last_sequence = max(self._last_sequence + 1, time.time_ns() // 1_000_000)
            return self._last_sequence

    def beat(self, *, ready: bool, readiness_code: str | None) -> int:
        response = self.client.post(
            self.settings.control_plane_url.rstrip("/") + "/api/v1/gateway-installations/heartbeat",
            headers={"Authorization": "Bearer " + self.settings.credential},
            json={
                "organization_id": self.settings.organization_id,
                "installation_id": self.settings.installation_id,
                "application_id": self.settings.application_id,
                "route_sha256": self.settings.route_sha256,
                "sequence": self._next_sequence(),
                "version": GATEWAY_VERSION,
                "ready": ready,
                "readiness_code": None if ready else readiness_code,
            },
        )
        return response.status_code
