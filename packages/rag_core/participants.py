"""Participant-aware authorization for shared AI conversations.

When one generated answer is delivered to several people (a group chat, a
Teams/Slack channel bot, a multi-recipient email draft, an agent replying in a
thread), it is not enough that the *requester* may read the sources: every
person who will see the answer must be authorized for every source used.
Otherwise the assistant becomes a confused deputy that copies one employee's
documents to the others.

This follows the deterministic rule argued for in Microsoft Research's
position paper "Enterprise AI Must Enforce Participant-Aware Access Control"
(arXiv:2509.14608): a document may contribute to the response only if every
active participant is authorized for it.

``ParticipantAwareGuard`` wraps an ordinary Guard client and fans each Layer 1
and Layer 2 call out to every participant's *verified* identity token:

* Layer 1 returns the exact intersection of per-participant allow-lists. A
  chunk-level grant for one participant is never widened by another
  participant's whole-document grant.
* Layer 2 releases only if every participant's own Layer 2 allows, all under
  one identical authorization revision.
* Any participant failing authentication, a mode mismatch, or a revision
  disagreement fails the whole request closed.

The existing ``ProtectedRAG`` release logic (buffering, attestation, trace
completeness, late-source Layer 1, revision binding) is reused unchanged.
"""
from __future__ import annotations

from typing import Any, Protocol

from .protection import RetrievedResource, authorized_resources

MAX_PARTICIPANTS = 16


class _Guard(Protocol):
    def filter_resources(self, *, employee_token: str, application_id: str, request_id: str,
                         resources: list[RetrievedResource]) -> dict[str, Any]: ...

    def check_output(self, *, employee_token: str, application_id: str, request_id: str,
                     decision_id: str, resources: list[RetrievedResource],
                     additional_decision_ids: list[str] | None = None) -> dict[str, Any]: ...


def _key(item: RetrievedResource) -> tuple[str, str, str | None]:
    return item.source_id, item.resource_id, item.chunk_id


def _revision(result: dict[str, Any]) -> tuple[Any, Any]:
    return result.get("authorization_revision"), result.get("authorization_revision_hash")


class ParticipantAwareGuard:
    """Per-request adapter. Create a new instance for every protected request."""

    def __init__(self, guard: _Guard, primary_token: str, participant_tokens: list[str]) -> None:
        tokens = [primary_token, *[t for t in participant_tokens if t != primary_token]]
        unique = list(dict.fromkeys(tokens))
        if not primary_token or any(not isinstance(t, str) or not t for t in unique):
            raise ValueError("PARTICIPANT_TOKEN_INVALID")
        if len(unique) > MAX_PARTICIPANTS:
            raise ValueError("TOO_MANY_PARTICIPANTS")
        self.guard = guard
        self.primary = primary_token
        self.tokens = unique
        # combined decision id -> each participant's own decision id
        self._decision_map: dict[str, list[str]] = {}

    @property
    def participant_count(self) -> int:
        return len(self.tokens)

    def filter_resources(self, *, employee_token: str, application_id: str, request_id: str,
                         resources: list[RetrievedResource]) -> dict[str, Any]:
        if employee_token != self.primary:
            raise ValueError("PARTICIPANT_PRIMARY_TOKEN_MISMATCH")
        results = [self.guard.filter_resources(employee_token=token, application_id=application_id,
                                               request_id=request_id, resources=resources)
                   for token in self.tokens]
        modes = {result.get("mode", "protect") for result in results}
        if len(modes) != 1:
            raise ValueError("PARTICIPANT_MODE_MISMATCH")
        if len({_revision(result) for result in results}) != 1:
            raise ValueError("PARTICIPANT_REVISION_MISMATCH")
        # Exact intersection over (source, resource, chunk). Contradictory
        # per-participant grants already raise inside authorized_resources().
        allowed_keys: set[tuple[str, str, str | None]] | None = None
        for result in results:
            keys = {_key(item) for item in authorized_resources(resources, result)}
            allowed_keys = keys if allowed_keys is None else allowed_keys & keys
        allowed_keys = allowed_keys or set()
        allowed: list[dict[str, Any]] = []
        by_resource: dict[tuple[str, str], list[str | None]] = {}
        for item in resources:
            if _key(item) in allowed_keys:
                by_resource.setdefault((item.source_id, item.resource_id), []).append(item.chunk_id)
        for (source_id, resource_id), chunks in by_resource.items():
            if None in chunks:
                # A resource-level entry would authorize *every* chunk of this
                # resource. Only emit it if every retrieved chunk of the
                # resource survived the intersection; otherwise fail closed.
                retrieved = [i for i in resources if (i.source_id, i.resource_id) == (source_id, resource_id)]
                if any(_key(i) not in allowed_keys for i in retrieved):
                    raise ValueError("PARTICIPANT_GRANT_SCOPE_AMBIGUOUS")
                allowed.append({"source_id": source_id, "resource_id": resource_id, "chunk_ids": []})
            else:
                allowed.append({"source_id": source_id, "resource_id": resource_id,
                                "chunk_ids": sorted({c for c in chunks if c is not None})})
        mode = modes.pop()
        decision_id = str(results[0]["decision_id"])
        self._decision_map[decision_id] = [str(result["decision_id"]) for result in results]
        if mode == "protect":
            decision = "allow" if allowed else "block"
        else:
            decision = "would_allow" if allowed else "would_block"
        combined: dict[str, Any] = {
            "decision": decision, "mode": mode, "decision_id": decision_id,
            "allowed": allowed, "participants": len(self.tokens),
        }
        revision, revision_hash = _revision(results[0])
        if revision is not None:
            combined["authorization_revision"] = revision
            combined["authorization_revision_hash"] = revision_hash
        return combined

    def check_output(self, *, employee_token: str, application_id: str, request_id: str,
                     decision_id: str, resources: list[RetrievedResource],
                     additional_decision_ids: list[str] | None = None) -> dict[str, Any]:
        if employee_token != self.primary:
            raise ValueError("PARTICIPANT_PRIMARY_TOKEN_MISMATCH")
        primary_ids = self._decision_map.get(decision_id)
        extra = [self._decision_map.get(value) for value in (additional_decision_ids or [])]
        if primary_ids is None or any(ids is None for ids in extra):
            raise ValueError("PARTICIPANT_DECISION_UNKNOWN")
        results = []
        for index, token in enumerate(self.tokens):
            results.append(self.guard.check_output(
                employee_token=token, application_id=application_id, request_id=request_id,
                decision_id=primary_ids[index], resources=resources,
                additional_decision_ids=[ids[index] for ids in extra if ids is not None],
            ))
        if len({_revision(result) for result in results}) != 1:
            # Authorization changed for someone mid-request: never release.
            return {**results[0], "decision": "block", "reason": "PARTICIPANT_REVISION_MISMATCH"}
        for result in results:
            if result.get("decision") not in {"allow", "would_allow", "would_block"}:
                return result  # first participant who is not authorized decides
        decisions = {result.get("decision") for result in results}
        if decisions == {"allow"}:
            return results[0]
        if "allow" in decisions:
            # Mixed protect/shadow answers are contradictory: fail closed.
            return {**results[0], "decision": "block", "reason": "PARTICIPANT_MODE_MISMATCH"}
        return results[0] if "would_block" not in decisions else next(r for r in results if r.get("decision") == "would_block")
