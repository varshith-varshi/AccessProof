"""Two-layer, fail-closed access Guard.

Layer 1 (before results are shown): removes every catalogue item the member may not use,
so restricted titles never appear in search, recommendations or availability views.
Each item that passes is returned with a signed *attestation* (book, collection, member,
policy revision, expiry) - the library's equivalent of signed retrieval lineage.

Layer 2 (before release): when a member borrows, reserves or opens digital content, the
Guard verifies the attestation (no tampering, same member, same book, not expired) and
re-checks access against the *current* authoritative policy. A revocation that lands
between search and checkout therefore blocks the release.

The Guard fails closed: if identity, policy freshness, the Guard itself or the
attestation cannot be verified, the answer is "deny".
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .clock import Clock
from .db import Database
from .identity import IdentityError, sign, verify
from .policy import PolicySnapshot, PolicyStore

SUPPORTED_RELEASE_PATHS = frozenset({"checkout", "reserve", "read_digital", "renew"})


class GuardError(Exception):
    """A fail-closed refusal. ``code`` is a stable machine-readable reason."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    revision: int


class Guard:
    def __init__(
        self,
        db: Database,
        store: PolicyStore,
        clock: Clock,
        secret: str,
        max_staleness_seconds: int,
        attestation_ttl_seconds: int,
    ) -> None:
        self._db = db
        self._store = store
        self._clock = clock
        self._secret = secret
        self._max_staleness = max_staleness_seconds
        self._attestation_ttl = attestation_ttl_seconds
        self._installed: PolicySnapshot | None = None
        self._installed_at: float = 0.0
        self.enabled = True

    # --- policy installation -----------------------------------------------------------
    def sync(self) -> int:
        """Install the newest policy revision (called by the reconciliation worker)."""
        self._installed = self._store.snapshot()
        self._installed_at = self._clock.now()
        self.audit(None, "policy_sync", None, "info", "installed policy", self._installed.revision)
        return self._installed.revision

    @property
    def installed_revision(self) -> int:
        return self._installed.revision if self._installed else 0

    def status(self) -> dict:
        age = self._clock.now() - self._installed_at if self._installed else None
        return {
            "enabled": self.enabled,
            "installed_revision": self.installed_revision,
            "authoritative_revision": self._store.current_revision(),
            "policy_age_seconds": age,
            "max_staleness_seconds": self._max_staleness,
            "ready": self._ready_reason() is None,
            "not_ready_reason": self._ready_reason(),
        }

    def _ready_reason(self) -> str | None:
        if not self.enabled:
            return "guard_unavailable"
        if self._installed is None:
            return "policy_not_installed"
        if self._clock.now() - self._installed_at > self._max_staleness:
            return "policy_stale"
        return None

    def _require_ready(self) -> PolicySnapshot:
        reason = self._ready_reason()
        if reason is not None:
            raise GuardError(reason, f"Guard cannot decide safely ({reason}); request denied")
        assert self._installed is not None
        return self._installed

    # --- Layer 1 -----------------------------------------------------------------------
    def layer1_filter(self, member_id: str, books: Iterable[dict]) -> list[dict]:
        snap = self._require_ready()
        allowed: list[dict] = []
        hidden = 0
        for book in books:
            ok, _ = snap.can_access(member_id, book["collection_id"])
            if ok:
                allowed.append({**book, "attestation": self._attest(member_id, book, snap.revision)})
            else:
                hidden += 1
        if hidden:
            self.audit(member_id, "layer1_filter", None, "deny", f"hid {hidden} restricted item(s)", snap.revision)
        return allowed

    def _attest(self, member_id: str, book: dict, revision: int) -> str:
        return sign(
            self._secret,
            {
                "typ": "attestation",
                "book": book["id"],
                "col": book["collection_id"],
                "sub": member_id,
                "rev": revision,
                "exp": self._clock.now() + self._attestation_ttl,
            },
        )

    # --- Layer 2 -----------------------------------------------------------------------
    def layer2_release(self, member_id: str, book: dict, attestation: str | None, path: str) -> Decision:
        """Verify lineage + current access before anything is released. Raises GuardError on deny."""
        try:
            self._require_ready()
            if path not in SUPPORTED_RELEASE_PATHS:
                raise GuardError("unsupported_output_path", f"release path '{path}' is not supported")
            self._check_attestation(member_id, book, attestation)
            # Re-check against the authoritative policy right now, not the installed copy:
            current = self._store.snapshot()
            if current.revision != self.installed_revision:
                self.sync()  # newer revision exists: install it before deciding
            ok, reason = current.can_access(member_id, book["collection_id"])
            if not ok:
                raise GuardError("access_revoked", f"access denied at release: {reason}")
        except GuardError as err:
            self.audit(member_id, f"layer2_{path}", book["id"], "deny", err.code, self.installed_revision)
            raise
        self.audit(member_id, f"layer2_{path}", book["id"], "allow", reason, current.revision)
        return Decision(True, reason, current.revision)

    def _check_attestation(self, member_id: str, book: dict, attestation: str | None) -> None:
        if not attestation:
            raise GuardError("missing_attestation", "item was not obtained through an authorised search")
        try:
            claims = verify(self._secret, attestation)
        except IdentityError as exc:
            raise GuardError("invalid_attestation", f"attestation rejected: {exc}") from exc
        if claims.get("typ") != "attestation":
            raise GuardError("invalid_attestation", "not an attestation")
        if claims.get("sub") != member_id:
            raise GuardError("invalid_attestation", "attestation issued to a different member")
        if claims.get("book") != book["id"] or claims.get("col") != book["collection_id"]:
            raise GuardError("invalid_attestation", "attestation does not match this item")
        if float(claims.get("exp", 0)) < self._clock.now():
            raise GuardError("attestation_expired", "attestation expired; search again")

    # --- audit -------------------------------------------------------------------------
    def audit(
        self,
        member_id: str | None,
        action: str,
        resource: str | None,
        decision: str,
        reason: str,
        revision: int | None,
    ) -> None:
        with self._db.tx() as c:
            c.execute(
                "INSERT INTO audit_log (at, member_id, action, resource, decision, reason, policy_revision)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (self._clock.now(), member_id, action, resource, decision, reason, revision),
            )
