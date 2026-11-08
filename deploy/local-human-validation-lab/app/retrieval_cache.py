"""Short-lived, signed-candidate retrieval cache for the local protected RAG.

This cache never stores an allowed-resource decision or an LLM answer.
A hit returns *untrusted candidates* with original ingestion signatures:
the existing Gateway/Guard MUST freshly authorize each resource and verify
each signature before it may reach the model. No direct model fallback.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from typing import Any

import redis

from app.index import Match

FIELDS = frozenset(Match.__dataclass_fields__)
MAX_CANDIDATES = 5
MAX_VALUE_BYTES = 180_000


class CacheUnavailable(RuntimeError):
    """A cache lookup error is not permission to run an unprotected route."""


def cache_key(*, tenant: str, source: str, application: str, generation: str,
              question: str, document_name: str | None) -> str:
    if not all((tenant, source, application, generation)):
        raise ValueError("CACHE_SCOPE_OR_INDEX_GENERATION_REQUIRED")
    key_material = json.dumps(
        ["signed-retrieval-candidates/v1", tenant, source, application, generation,
         question.strip(), document_name or ""], ensure_ascii=True, separators=(",", ":")
    )
    return "ap:protected:candidates:v1:" + hashlib.sha256(key_material.encode()).hexdigest()


def _strict_matches(value: Any) -> list[Match]:
    if (not isinstance(value, list) or not 1 <= len(value) <= MAX_CANDIDATES):
        raise CacheUnavailable("CACHED_RETRIEVAL_INVALID")
    candidates: list[Match] = []
    for record in value:
        if not isinstance(record, dict) or set(record) != FIELDS:
            raise CacheUnavailable("CACHED_RETRIEVAL_INVALID")
        try:
            candidate = Match(**record)
        except (TypeError, ValueError) as exc:
            raise CacheUnavailable("CACHED_RETRIEVAL_INVALID") from exc
        if (any(not isinstance(x, str) or not x for x in (
                candidate.doc_id, candidate.chunk_id, candidate.text, candidate.version,
                candidate.name, candidate.attestation))
                or not isinstance(candidate.url, str)
                or not isinstance(candidate.score, (float, int))
                or isinstance(candidate.score, bool)
                or len(candidate.text) > 100_000
                or len(candidate.attestation) > 16_000):
            raise CacheUnavailable("CACHED_RETRIEVAL_INVALID")
        candidates.append(candidate)
    return candidates


def get_or_retrieve(
    *, cache: Any, index: Any, tenant: str, source: str, application: str,
    generation: str, question: str, document_name: str | None,
    ttl_seconds: int = 45,
) -> tuple[list[Match], bool]:
    """Get candidate chunks, NEVER reusing a prior employee's authorization.

    Cache is bounded to the exact tenant/source/application, question and
    atomic source-index generation; short TTL cannot outlive attestation
    freshness checks performed on every protected request. All candidates,
    cached or freshly queried, must pass through Gateway on this request.
    """
    if not 1 <= ttl_seconds <= 90:
        raise ValueError("UNSAFE_RETRIEVAL_CACHE_TTL")
    key = cache_key(
        tenant=tenant, source=source, application=application, generation=generation,
        question=question, document_name=document_name,
    )
    try:
        raw = cache.get(key)
    except redis.RedisError as exc:
        raise CacheUnavailable("SIGNED_RETRIEVAL_CACHE_UNAVAILABLE") from exc
    if raw is not None:
        if not isinstance(raw, (bytes, str)) or len(raw) > MAX_VALUE_BYTES:
            raise CacheUnavailable("CACHED_RETRIEVAL_INVALID")
        try:
            record = json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise CacheUnavailable("CACHED_RETRIEVAL_INVALID") from exc
        if (not isinstance(record, dict) or set(record) != {"generation", "candidates"}
                or record["generation"] != generation):
            raise CacheUnavailable("CACHED_RETRIEVAL_GENERATION_INVALID")
        return _strict_matches(record["candidates"]), True

    matches = (index.by_name(document_name, limit=MAX_CANDIDATES)
               if document_name else index.search(question, limit=MAX_CANDIDATES))
    if not matches:
        return [], False
    payload = json.dumps({
        "generation": generation, "candidates": [asdict(x) for x in matches],
    }, separators=(",", ":"), ensure_ascii=True)
    if len(payload) > MAX_VALUE_BYTES:
        # No truncated content or unsigned silent fallback.
        raise CacheUnavailable("SIGNED_RETRIEVAL_CACHE_VALUE_TOO_LARGE")
    try:
        cache.setex(key, ttl_seconds, payload)
    except redis.RedisError as exc:
        raise CacheUnavailable("SIGNED_RETRIEVAL_CACHE_UNAVAILABLE") from exc
    return matches, False
