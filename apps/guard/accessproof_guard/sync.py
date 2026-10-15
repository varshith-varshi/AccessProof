"""Machine-only control-plane synchronization for a customer-side Guard."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from .cache import PolicyCache


@dataclass(frozen=True)
class GuardMachineCredentials:
    control_plane_url: str
    guard_id: str
    credential: str
    version: str


class GuardSyncClient:
    def __init__(self, cache: PolicyCache, credentials: GuardMachineCredentials, client: httpx.Client | None = None) -> None:
        self.cache = cache
        self.credentials = credentials
        self.client = client or httpx.Client(timeout=10, follow_redirects=False, trust_env=False)
        self._owns_client = client is None

    @property
    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.credentials.credential}"}

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    def _ack(self, version: int, status: str) -> None:
        response = self.client.post(
            f"{self.credentials.control_plane_url.rstrip('/')}/api/v1/guards/policies/ack",
            headers=self._headers,
            json={"guard_id": self.credentials.guard_id, "policy_version": version, "status": status},
        )
        response.raise_for_status()

    def _fetch(self, *, full_snapshot: bool) -> dict[str, Any]:
        response = self.client.get(
            f"{self.credentials.control_plane_url.rstrip('/')}/api/v1/guards/{self.credentials.guard_id}/policies",
            headers=self._headers,
            params={"after_version": self.cache.version(), "full_snapshot": str(full_snapshot).lower()},
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("version"), int):
            raise ValueError("Invalid policy synchronization response")
        return data

    def sync_once(self) -> bool:
        payload = self._fetch(full_snapshot=False)
        version = int(payload["version"])
        if version < self.cache.version():
            raise ValueError("STALE_POLICY")
        policies = payload.get("policies", [])
        if version > self.cache.version() and not policies:
            payload = self._fetch(full_snapshot=True)
            version = int(payload["version"])
        full = payload.get("kind") == "full"
        decisions = payload.get("decisions", []) if full else payload.get("policies", [])
        if version == self.cache.version():
            return False
        if not isinstance(decisions, list):
            raise ValueError("Invalid policy decision set")
        # Incremental payloads preserve every committed policy version.  ACK
        # each one so the control plane's delivery record remains accurate;
        # a full snapshot has only the aggregate version and is acknowledged
        # at that version.
        versions = [version] if full else sorted({int(row["version"]) for row in decisions})
        for policy_version in versions:
            self._ack(policy_version, "received")
        installed = self.cache.install(version, decisions, full_snapshot=full)
        if installed:
            for policy_version in versions:
                self._ack(policy_version, "installed")
        return installed

    def heartbeat(self, *, degraded_conditions: list[str] | None = None) -> None:
        response = self.client.post(
            f"{self.credentials.control_plane_url.rstrip('/')}/api/v1/guards/heartbeat",
            headers=self._headers,
            json={
                "guard_id": self.credentials.guard_id,
                "version": self.credentials.version,
                "active_policy_version": self.cache.version(),
                "cache_status": "healthy" if not degraded_conditions else "degraded",
                "degraded_conditions": degraded_conditions or [],
            },
        )
        response.raise_for_status()

    def upload_audit(self) -> int:
        events = self.cache.pending_audit()
        if not events:
            return 0
        response = self.client.post(
            f"{self.credentials.control_plane_url.rstrip('/')}/api/v1/guards/audit-events",
            headers=self._headers,
            json={"guard_id": self.credentials.guard_id, "events": events},
        )
        response.raise_for_status()
        self.cache.mark_audit_delivered([str(event["event_id"]) for event in events])
        return len(events)
