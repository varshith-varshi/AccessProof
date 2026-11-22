"""Versioned access policy.

``PolicyStore`` is the authoritative permission source (the library's equivalent of
SharePoint/Entra ACLs). Every change to grants, memberships or member status produces a
new policy revision. The Guard installs snapshots of this policy and evaluates them.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .clock import Clock
from .db import Database

EVERYONE = "everyone"


@dataclass(frozen=True)
class PolicySnapshot:
    revision: int
    taken_at: float
    active_members: frozenset[str]
    member_groups: dict[str, frozenset[str]] = field(default_factory=dict)
    # collection_id -> set of ("member"|"group", principal_id)
    grants: dict[str, frozenset[tuple[str, str]]] = field(default_factory=dict)

    def can_access(self, member_id: str, collection_id: str) -> tuple[bool, str]:
        """Effective access: a direct grant OR any group grant. Returns (allowed, reason)."""
        if member_id not in self.active_members:
            return False, "member inactive or unknown"
        grants = self.grants.get(collection_id, frozenset())
        if ("member", member_id) in grants:
            return True, "direct grant"
        if ("group", EVERYONE) in grants:
            return True, "public collection"
        for group in sorted(self.member_groups.get(member_id, frozenset())):
            if ("group", group) in grants:
                return True, f"group grant: {group}"
        return False, "no grant for this collection"


class PolicyStore:
    def __init__(self, db: Database, clock: Clock) -> None:
        self._db = db
        self._clock = clock
        if self.current_revision() == 0:
            self._bump("initial policy")

    # --- revisions -----------------------------------------------------------------
    def current_revision(self) -> int:
        row = self._db.one("SELECT MAX(revision) AS r FROM policy_revisions")
        return int(row["r"] or 0)

    def _bump(self, reason: str) -> int:
        with self._db.tx() as c:
            cur = c.execute(
                "INSERT INTO policy_revisions (created_at, reason) VALUES (?, ?)", (self._clock.now(), reason)
            )
            return int(cur.lastrowid)

    def snapshot(self) -> PolicySnapshot:
        active = frozenset(r["id"] for r in self._db.query("SELECT id FROM members WHERE active = 1"))
        groups: dict[str, set[str]] = {}
        for r in self._db.query("SELECT member_id, group_id FROM memberships"):
            groups.setdefault(r["member_id"], set()).add(r["group_id"])
        grants: dict[str, set[tuple[str, str]]] = {}
        for r in self._db.query("SELECT collection_id, principal_type, principal_id FROM grants"):
            grants.setdefault(r["collection_id"], set()).add((r["principal_type"], r["principal_id"]))
        return PolicySnapshot(
            revision=self.current_revision(),
            taken_at=self._clock.now(),
            active_members=active,
            member_groups={k: frozenset(v) for k, v in groups.items()},
            grants={k: frozenset(v) for k, v in grants.items()},
        )

    def record_change(self, reason: str) -> int:
        """Issue a new revision for a change made outside the mutation helpers (e.g. demo data)."""
        return self._bump(reason)

    # --- mutations (each one issues a new revision) ----------------------------------
    def grant(self, collection_id: str, principal_type: str, principal_id: str) -> int:
        with self._db.tx() as c:
            c.execute(
                "INSERT OR IGNORE INTO grants (collection_id, principal_type, principal_id) VALUES (?, ?, ?)",
                (collection_id, principal_type, principal_id),
            )
        return self._bump(f"grant {principal_type}:{principal_id} -> {collection_id}")

    def revoke(self, collection_id: str, principal_type: str, principal_id: str) -> int:
        with self._db.tx() as c:
            c.execute(
                "DELETE FROM grants WHERE collection_id = ? AND principal_type = ? AND principal_id = ?",
                (collection_id, principal_type, principal_id),
            )
        return self._bump(f"revoke {principal_type}:{principal_id} -> {collection_id}")

    def add_membership(self, member_id: str, group_id: str) -> int:
        with self._db.tx() as c:
            c.execute("INSERT OR IGNORE INTO memberships (member_id, group_id) VALUES (?, ?)", (member_id, group_id))
        return self._bump(f"add {member_id} to {group_id}")

    def remove_membership(self, member_id: str, group_id: str) -> int:
        with self._db.tx() as c:
            c.execute("DELETE FROM memberships WHERE member_id = ? AND group_id = ?", (member_id, group_id))
        return self._bump(f"remove {member_id} from {group_id}")

    def set_member_active(self, member_id: str, active: bool) -> int:
        with self._db.tx() as c:
            c.execute("UPDATE members SET active = ? WHERE id = ?", (1 if active else 0, member_id))
        return self._bump(f"{'activate' if active else 'suspend'} {member_id}")
