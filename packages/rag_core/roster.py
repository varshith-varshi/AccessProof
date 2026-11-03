"""Trusted conversation rosters for shared AI conversations (R-1 completion).

Participant tokens submitted by the caller prove *who they are*, not that they
are *everyone* who will see the answer: a caller can simply omit a recipient.
A roster closes that gap. A trusted platform adapter (the Teams/Slack
integration, holding an Ed25519 key the Gateway pins) signs a short-lived
statement of the conversation's complete membership. The Gateway requires the
verified participant identities to equal the roster exactly; any missing or
extra identity fails closed.

Wire format: ``base64url(json payload) "." base64url(Ed25519 signature)``.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROSTER_SCHEMA = "accessproof.conversation_roster/v1"
MAX_MEMBERS = 16
_KEY_ID = re.compile(r"^[A-Za-z0-9._-]{1,32}$")


class RosterError(ValueError):
    pass


@dataclass(frozen=True)
class Roster:
    conversation_id: str
    members: frozenset[tuple[str, str]]  # (issuer, subject)
    issued_at: int
    nonce: str


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign_roster(payload: Mapping[str, Any], private_key: Ed25519PrivateKey) -> str:
    """Adapter-side signing (never used by the Gateway itself)."""
    body = json.dumps(dict(payload), sort_keys=True, separators=(",", ":")).encode()
    return _b64(body) + "." + _b64(private_key.sign(body))


class RosterVerifier:
    def __init__(self, *, tenant_id: str, application_id: str,
                 trusted_keys: Mapping[str, Ed25519PublicKey], max_age_seconds: int = 120) -> None:
        if not trusted_keys or not all(_KEY_ID.fullmatch(k) for k in trusted_keys):
            raise ValueError("Roster verifier requires pinned adapter keys")
        if not 10 <= max_age_seconds <= 600:
            raise ValueError("Roster freshness window unsafe")
        self.tenant_id, self.application_id = tenant_id, application_id
        self.trusted_keys = dict(trusted_keys)
        self.max_age_seconds = max_age_seconds

    def verify(self, token: str, *, now: float | None = None) -> Roster:
        try:
            body_b64, sig_b64 = token.split(".")
            body, signature = _unb64(body_b64), _unb64(sig_b64)
            payload = json.loads(body)
        except (ValueError, binascii.Error, json.JSONDecodeError) as exc:
            raise RosterError("ROSTER_MALFORMED") from exc
        if not isinstance(payload, dict) or payload.get("schema") != ROSTER_SCHEMA:
            raise RosterError("ROSTER_SCHEMA_INVALID")
        key = self.trusted_keys.get(str(payload.get("key_id")))
        if key is None:
            raise RosterError("ROSTER_KEY_UNTRUSTED")
        try:
            key.verify(signature, body)
        except InvalidSignature as exc:
            raise RosterError("ROSTER_SIGNATURE_INVALID") from exc
        if payload.get("tenant_id") != self.tenant_id or payload.get("application_id") != self.application_id:
            raise RosterError("ROSTER_BINDING_MISMATCH")
        issued = payload.get("issued_at")
        current = time.time() if now is None else now
        if type(issued) is not int or issued > current + 5 or current - issued > self.max_age_seconds:
            raise RosterError("ROSTER_STALE")
        members_raw = payload.get("members")
        if (not isinstance(members_raw, list) or not 1 <= len(members_raw) <= MAX_MEMBERS
                or not all(isinstance(m, dict) and isinstance(m.get("issuer"), str) and m["issuer"]
                           and isinstance(m.get("subject"), str) and m["subject"] for m in members_raw)):
            raise RosterError("ROSTER_MEMBERS_INVALID")
        members = frozenset((m["issuer"], m["subject"]) for m in members_raw)
        conversation = payload.get("conversation_id")
        nonce = payload.get("nonce")
        if (len(members) != len(members_raw) or not isinstance(conversation, str) or not conversation
                or not isinstance(nonce, str) or len(nonce) < 16):
            raise RosterError("ROSTER_MEMBERS_INVALID")
        return Roster(conversation_id=conversation, members=members, issued_at=issued, nonce=nonce)
