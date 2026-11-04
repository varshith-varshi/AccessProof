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
            params={"after_version": self.cache.version(), "full_snapshot": str(full_snapshot).lower(),
                    **({"identity_version": known} if (known := self.cache.reusable_identity_version()) else {}),
                    **({"content_versions_digest": vd} if (vd := self.cache.resource_versions_digest()) else {})},
        )
        response.raise_for_status()
        data = response.json()
        data["_identity_version_sent"] = known
        data["_versions_digest_sent"] = vd
        if not isinstance(data, dict) or not isinstance(data.get("version"), int):
            raise ValueError("Invalid policy synchronization response")
        return data

    def wait_for_policy_update(self, *, wait_seconds: int = 20) -> bool:
        """Hold an authenticated outbound request until policy state advances.

        A notification is never policy content. The caller must still execute
        ``sync_once`` to fetch and atomically install the authoritative state.
        """
        token = getattr(self, "_authorization_state_token", None)
        response = self.client.get(
            f"{self.credentials.control_plane_url.rstrip('/')}/api/v1/guards/{self.credentials.guard_id}/policy-notifications",
            headers=self._headers,
            params={"after_version": self.cache.version(), "wait_seconds": min(25, max(0, wait_seconds)),
                    **({"state_token": token} if token else {})},
            # The server holds the request open up to wait_seconds.
            timeout=httpx.Timeout(min(25, max(0, wait_seconds)) + 10.0),
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict) or payload.get("guard_id") != self.credentials.guard_id:
            raise ValueError("Invalid policy notification")
        version = payload.get("policy_version")
        if not isinstance(version, int) or version < self.cache.version():
            raise ValueError("Invalid policy notification")
        if payload.get("event_type") == "AUTHORIZATION_STATE_CHANGED":
            return True
        return payload.get("event_type") == "POLICY_UPDATE_AVAILABLE" and version > self.cache.version()

    def sync_once(self) -> bool:
        payload = self._fetch(full_snapshot=False)
        version = int(payload["version"])
        if version < self.cache.version():
            # No untrusted/stale response may modify Guard application modes.
            raise ValueError("STALE_POLICY")
        policies = payload.get("policies", [])
        if version > self.cache.version() and not policies:
            payload = self._fetch(full_snapshot=True)
            version = int(payload["version"])
            if version < self.cache.version():
                raise ValueError("STALE_POLICY")

        bindings = payload.get("applications")
        # Older control planes have no mapping envelope. Treat it as an empty
        # authoritative snapshot so bound applications fail closed at lookup.
        mappings = payload.get("identity_mappings", [])
        if not isinstance(bindings, list):
            raise ValueError("MISSING_APPLICATION_BINDINGS")
        for binding in bindings:
            if not isinstance(binding, dict):
                raise ValueError("INVALID_APPLICATION_BINDINGS")
            # A missing health field must never turn an unknown or stale ACL
            # state into a healthy Protect binding during synchronization.
            if binding.get("mode") == "protect" and not isinstance(
                binding.get("source_acl_healthy"), bool
            ):
                raise ValueError("SOURCE_ACL_HEALTH_REQUIRED")
        identity_unchanged = (
            payload.get("identity_mappings_unchanged") is True
            and isinstance(payload.get("_identity_version_sent"), str)
            and payload.get("identity_version") == payload.get("_identity_version_sent")
        )
        if identity_unchanged:
            mappings = None  # keep the installed verified set (bounded by the forced refresh)
        elif not isinstance(mappings, list):
            raise ValueError("MISSING_IDENTITY_MAPPINGS")
        revisions = payload.get("authorization_revisions")
        if revisions is not None and not isinstance(revisions, list):
            raise ValueError("INVALID_AUTHORIZATION_REVISIONS")
        # Validate authorization and identity snapshots before any policy
        # mutation or ACK. A malformed revision cannot leave a newer ALLOW
        # installed with an older or rejected authorization boundary.
        if mappings is not None:
            self.cache.validate_identity_mappings(mappings)
        if revisions is not None:
            self.cache.validate_authorization_revisions(revisions)
        full = payload.get("kind") == "full"
        decisions = payload.get("decisions", []) if full else payload.get("policies", [])
        if not isinstance(decisions, list):
            raise ValueError("Invalid policy decision set")
        # Received ACK is informational; installed ACK is sent *only* after
        # the whole authorization snapshot commits as one SQLite transaction.
        versions = [version] if full else sorted({int(row["version"]) for row in decisions})
        if version > self.cache.version():
            for policy_version in versions:
                self._ack(policy_version, "received")
        installed = self.cache.apply_sync_snapshot(
            version, decisions, full_snapshot=full, applications=bindings,
            mappings=mappings, revisions=revisions,
            ack_versions=versions if version > self.cache.version() else [],
            identity_version=payload.get("identity_version") if isinstance(payload.get("identity_version"), str) else None,
            resource_versions=self._resource_versions(payload),
            resource_versions_digest=payload.get("resource_versions_digest") if isinstance(payload.get("resource_versions_digest"), str) else None,
        )
        # Do not lose an installed ACK if the HTTP request, the API, or the
        # Guard process crashes after the SQLite commit. Pending versions are
        # persisted in the same transaction as the installed policy snapshot.
        for policy_version in self.cache.pending_installed_policy_acks():
            self._ack(policy_version, "installed")
            self.cache.mark_installed_policy_ack_delivered(policy_version)
        # Only a fully applied envelope may set the token used for wake-ups;
        # a failed sync keeps the old token, so the Guard keeps being woken.
        token = payload.get("authorization_state_token")
        self._authorization_state_token = token if isinstance(token, str) and len(token) <= 64 else None
        return installed

    @staticmethod
    def _resource_versions(payload: dict[str, Any]) -> dict[str, Any] | None | bool:
        """False = keep installed set; None = control plane sends none (drop)."""
        if (payload.get("resource_versions_unchanged") is True
                and isinstance(payload.get("_versions_digest_sent"), str)
                and payload.get("resource_versions_digest") == payload.get("_versions_digest_sent")):
            return False
        value = payload.get("resource_versions")
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ValueError("INVALID_RESOURCE_VERSIONS")
        return value

    def heartbeat(self, *, degraded_conditions: list[str] | None = None) -> None:
        # An enrolled Guard without an installed policy is NOT healthy.
        # Distinguish machine connectivity from data-plane authorization readiness.
        conditions = list(degraded_conditions or [])
        if self.cache.version() <= 0:
            conditions.append("POLICY_NOT_INSTALLED")
        if self.cache.sync_age_seconds() is None:
            conditions.append("POLICY_NEVER_SYNCED")
        if not self.cache.all_protect_sources_healthy():
            conditions.append("SOURCE_AUTHORIZATION_STALE")
        if self.cache.authorization_revisions_received() and not self.cache.all_protect_revisions_present():
            conditions.append("AUTHORIZATION_REVISION_MISSING")
        if not self.cache.audit_has_capacity():
            conditions.append("AUDIT_BACKLOG_FULL")
        response = self.client.post(
            f"{self.credentials.control_plane_url.rstrip('/')}/api/v1/guards/heartbeat",
            headers=self._headers,
            json={
                "guard_id": self.credentials.guard_id,
                "version": self.credentials.version,
                "active_policy_version": self.cache.version(),
                "presence_sequence": self.cache.next_presence_sequence(),
                "cache_status": "healthy" if not conditions else "degraded",
                "degraded_conditions": conditions,
                "active_applications": self.cache.application_modes(),
                # The control plane compares this with its current signed
                # revision. Reporting an outdated revision is not a bypass:
                # it makes Guard lag observable instead of inferred.
                "active_authorization_revisions": self.cache.authorization_revision_snapshot(),
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
