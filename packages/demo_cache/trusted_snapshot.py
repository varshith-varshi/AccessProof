"""Bounded, short-lived, source-attested snapshot consumed by a protected RAG.

The independent Google Drive ingester writes the file with its private key.
The RAG process receives only the matching trusted public verification key.
A file path or document metadata is never permission or authenticity evidence.
"""
from __future__ import annotations

import json
import os
import secrets
import stat
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from packages.rag_core import (
    ContentBinding, RetrievedResource, SourceAttestationVerifier,
)


class SnapshotInvalid(ValueError):
    pass


def write_snapshot(path: Path, *, tenant_id: str, application_id: str,
                   source_id: str, resources: list[RetrievedResource],
                   now: int | None = None) -> None:
    """Atomically replace a customer-owned ingestion snapshot (never a symlink)."""
    if not all((tenant_id, application_id, source_id)):
        raise SnapshotInvalid("SNAPSHOT_BINDING_REQUIRED")
    if not 1 <= len(resources) <= 200:
        raise SnapshotInvalid("SNAPSHOT_RESOURCE_COUNT_INVALID")
    if not path.parent.is_dir() or path.is_symlink():
        raise SnapshotInvalid("SNAPSHOT_DESTINATION_UNSAFE")
    body = {
        "contract": "accessproof.signed-drive-snapshot/v1",
        "tenant_id": tenant_id, "application_id": application_id,
        "source_id": source_id, "generated_at": int(time.time()) if now is None else int(now),
        "resources": [asdict(resource) for resource in resources],
    }
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(raw) > 2_000_000:
        raise SnapshotInvalid("SNAPSHOT_TOO_LARGE")
    fd = None
    # A unique temporary name prevents a crashed prior ingester from
    # permanently blocking snapshot publication on restart.
    temp = path.with_name(f".{path.name}.{secrets.token_hex(12)}.writing")
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as output:
            fd = None
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, path)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass


def load_snapshot(path: Path, *, verifier: SourceAttestationVerifier,
                  application_id: str, source_id: str,
                  max_age_seconds: int = 240, now: int | None = None) -> list[RetrievedResource]:
    """Reject stale, incomplete, forged or unexpectedly large signed source data."""
    timestamp = int(time.time()) if now is None else int(now)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 2_000_000 or info.st_size < 1:
                raise SnapshotInvalid("SNAPSHOT_FILE_UNSAFE")
            with os.fdopen(fd, "rb") as input_file:
                fd = -1
                raw = input_file.read(2_000_001)
        finally:
            if fd != -1:
                os.close(fd)
        data: Any = json.loads(raw)
        if (not isinstance(data, dict) or data.get("contract") != "accessproof.signed-drive-snapshot/v1"
                or data.get("tenant_id") != verifier.tenant_id
                or data.get("application_id") != application_id
                or data.get("source_id") != source_id
                or type(data.get("generated_at")) is not int
                or not 0 <= timestamp - data["generated_at"] <= max_age_seconds):
            raise SnapshotInvalid("SNAPSHOT_BINDING_OR_FRESHNESS_INVALID")
        entries = data.get("resources")
        if not isinstance(entries, list) or not 1 <= len(entries) <= 200:
            raise SnapshotInvalid("SNAPSHOT_ENTRIES_INVALID")
        resources: list[RetrievedResource] = []
        seen: set[tuple[str, str, str | None]] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise SnapshotInvalid("SNAPSHOT_ENTRIES_INVALID")
            resource = RetrievedResource(**entry)
            # The one-source reference snapshot must not let a caller promote
            # an authenticated retrieval chunk into a fabricated tool/source
            # lineage type by modifying unsigned metadata.
            if (not resource.resource_id or resource.source_id != source_id
                    or not resource.content or resource.derived_type != "retrieval"
                    or resource.derived_id is not None):
                raise SnapshotInvalid("SNAPSHOT_ENTRIES_INVALID")
            identity = (resource.source_id, resource.resource_id, resource.chunk_id)
            if identity in seen:
                raise SnapshotInvalid("SNAPSHOT_DUPLICATE_RESOURCE")
            seen.add(identity)
            if resource.content_version is None:
                raise SnapshotInvalid("SNAPSHOT_MISSING_SOURCE_VERSION")
            verifier.verify(ContentBinding(
                tenant_id=verifier.tenant_id, application_id=application_id,
                source_id=resource.source_id, resource_id=resource.resource_id,
                chunk_id=resource.chunk_id, content_version=resource.content_version,
                content=resource.content,
            ), resource.content_attestation, now=timestamp)
            resources.append(resource)
        return resources
    except (OSError, ValueError, TypeError, UnicodeDecodeError) as exc:
        raise SnapshotInvalid("TRUSTED_SOURCE_SNAPSHOT_INVALID") from exc
