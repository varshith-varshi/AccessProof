"""Signed trusted-ingestion evidence manifests (``accessproof.evidence-manifest/v1``).

A manifest is the complete, current set of attested chunks for ONE
tenant/application/source, produced inside the trusted-ingestion environment:

    {"schema", "tenant_id", "application_id", "source_id", "seq", "generated_at",
     "expires_at", "previous_sha256", "manifest_key_id",
     "documents": [{"resource_id", "content_version", "name", "deleted": false}],
     "chunks": [{"resource_id", "chunk_id", "content_version", "content_sha256",
                 "content", "content_attestation"}],
     "signature"}

Rules (enforced by ``verify_manifest``, used by the Gateway before serving and
by every remote RAG before use):
  * Ed25519 signature by a pinned manifest key over the canonical JSON.
  * Exact tenant/application/source binding (cross-tenant manifests rejected).
  * Monotonic ``seq`` (no rollback to older evidence); equal seq only for the
    identical manifest.
  * Every chunk's per-chunk attestation is verified with the pinned ingestion
    keys and must match the manifest entry: source, resource, chunk, version
    and sha256 of the exact content bytes.
  * ``expires_at`` is the EARLIEST attestation expiry; never later. A manifest
    past ``expires_at`` is unusable: the client fails closed. A refresh failure
    never extends anything; the old manifest simply expires.

Manifests carry provenance only. They grant no authorization: every answer still
goes through Guard Layer 1, Layer 2 and the certified Gateway route.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA = "accessproof.evidence-manifest/v1"
MAX_ATTESTATION_TTL = 3600        # the attestation contract's own ceiling


class ManifestError(ValueError):
    pass


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def manifest_sha256(manifest: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical(dict(manifest))).hexdigest()


def attestation_claims(token: str) -> dict:
    try:
        payload, _sig = token.split(".", 1)
        claims = json.loads(_unb64(payload))
    except (ValueError, AttributeError) as exc:
        raise ManifestError("ATTESTATION_MALFORMED") from exc
    if not isinstance(claims, dict):
        raise ManifestError("ATTESTATION_MALFORMED")
    return claims


def verify_attestation(token: str, keys: Mapping[str, Ed25519PublicKey]) -> dict:
    payload, sig = token.split(".", 1)
    claims = attestation_claims(token)
    key = keys.get(str(claims.get("kid")))
    if key is None:
        raise ManifestError("ATTESTATION_KEY_UNTRUSTED")
    try:
        key.verify(_unb64(sig), _unb64(payload))
    except Exception as exc:
        raise ManifestError("ATTESTATION_SIGNATURE_INVALID") from exc
    return claims


def build_manifest(*, tenant_id: str, application_id: str, source_id: str, seq: int,
                   documents: Iterable[Mapping[str, Any]], chunks: Iterable[Mapping[str, Any]],
                   attestation_keys: Mapping[str, Ed25519PublicKey], manifest_key: Ed25519PrivateKey,
                   manifest_key_id: str, previous_sha256: str, now: int, max_ttl: int = 1800,
                   min_remaining: int = 120) -> dict:
    """Build and sign a manifest from attestations produced IN THIS refresh cycle.

    Refuses (raises) instead of publishing anything questionable: an attestation
    that does not verify, does not match its content, was not issued for this
    binding, has a TTL above ``max_ttl``, or is about to expire."""
    docs = sorted(({"resource_id": str(d["resource_id"]), "content_version": str(d["content_version"]),
                    "name": str(d.get("name") or ""), "deleted": False} for d in documents),
                  key=lambda d: d["resource_id"])
    known = {d["resource_id"]: d["content_version"] for d in docs}
    out_chunks, expiries = [], []
    for c in chunks:
        token = str(c["content_attestation"])
        claims = verify_attestation(token, attestation_keys)
        content = str(c["content"])
        expect = {"tenant": tenant_id, "app": application_id, "source": source_id,
                  "resource": str(c["resource_id"]), "chunk": str(c["chunk_id"]),
                  "revision": str(c["content_version"]),
                  "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest()}
        if any(claims.get(k) != v for k, v in expect.items()):
            raise ManifestError("ATTESTATION_BINDING_MISMATCH")
        if known.get(expect["resource"]) != expect["revision"]:
            raise ManifestError("CHUNK_FOR_UNLISTED_DOCUMENT_VERSION")
        iat, exp = int(claims.get("iat", 0)), int(claims.get("exp", 0))
        if not (iat <= now + 30 and exp - iat <= min(max_ttl, MAX_ATTESTATION_TTL) and exp >= now + min_remaining):
            raise ManifestError("ATTESTATION_NOT_FRESH")
        expiries.append(exp)
        out_chunks.append({"resource_id": expect["resource"], "chunk_id": expect["chunk"],
                           "content_version": expect["revision"], "content_sha256": expect["sha256"],
                           "content": content, "content_attestation": token})
    if not out_chunks:
        raise ManifestError("EMPTY_EVIDENCE")
    out_chunks.sort(key=lambda c: (c["resource_id"], c["chunk_id"]))
    manifest = {"schema": SCHEMA, "tenant_id": tenant_id, "application_id": application_id, "source_id": source_id,
                "seq": int(seq), "generated_at": now, "expires_at": min(expiries),
                "previous_sha256": previous_sha256, "manifest_key_id": manifest_key_id,
                "documents": docs, "chunks": out_chunks}
    manifest["signature"] = _b64(manifest_key.sign(canonical(manifest)))
    return manifest


def verify_manifest(manifest: Mapping[str, Any], *, manifest_keys: Mapping[str, Ed25519PublicKey],
                    attestation_keys: Mapping[str, Ed25519PublicKey], tenant_id: str, application_id: str,
                    source_id: str, now: int, min_seq: int = 0, last_sha256: str | None = None) -> dict:
    """Return the manifest if (and only if) it is fully valid right now."""
    if not isinstance(manifest, Mapping) or manifest.get("schema") != SCHEMA:
        raise ManifestError("MANIFEST_SCHEMA_UNSUPPORTED")
    body = {k: v for k, v in manifest.items() if k != "signature"}
    key = manifest_keys.get(str(manifest.get("manifest_key_id")))
    if key is None:
        raise ManifestError("MANIFEST_KEY_UNTRUSTED")
    try:
        key.verify(_unb64(str(manifest.get("signature"))), canonical(body))
    except Exception as exc:
        raise ManifestError("MANIFEST_SIGNATURE_INVALID") from exc
    if (manifest.get("tenant_id"), manifest.get("application_id"), manifest.get("source_id")) != (
            tenant_id, application_id, source_id):
        raise ManifestError("MANIFEST_BINDING_MISMATCH")
    seq = int(manifest.get("seq", -1))
    if seq < min_seq or (seq == min_seq and last_sha256 is not None and manifest_sha256(manifest) != last_sha256):
        raise ManifestError("MANIFEST_ROLLBACK")
    if now >= int(manifest.get("expires_at", 0)):
        raise ManifestError("EVIDENCE_EXPIRED")
    versions = {d["resource_id"]: d["content_version"] for d in manifest.get("documents", [])}
    earliest = None
    for c in manifest.get("chunks", []):
        claims = verify_attestation(str(c["content_attestation"]), attestation_keys)
        expect = {"tenant": tenant_id, "app": application_id, "source": source_id, "resource": c["resource_id"],
                  "chunk": c["chunk_id"], "revision": c["content_version"],
                  "sha256": hashlib.sha256(str(c["content"]).encode("utf-8")).hexdigest()}
        if any(claims.get(k) != v for k, v in expect.items()) or c.get("content_sha256") != expect["sha256"]:
            raise ManifestError("CHUNK_ATTESTATION_MISMATCH")
        if versions.get(c["resource_id"]) != c["content_version"]:
            raise ManifestError("CHUNK_VERSION_NOT_IN_MANIFEST")
        if now >= int(claims.get("exp", 0)):
            raise ManifestError("EVIDENCE_EXPIRED")
        earliest = int(claims["exp"]) if earliest is None else min(earliest, int(claims["exp"]))
    if earliest is None or int(manifest["expires_at"]) > earliest:
        # expires_at may never claim more life than the attestations have.
        raise ManifestError("MANIFEST_EXPIRY_INCONSISTENT")
    return dict(manifest)


def iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()
