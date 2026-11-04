"""Distribution of refreshed trusted-ingestion manifests to REMOTE RAG hosts.

The trusted-ingestion refresher publishes signed manifests into a directory
that the Gateway mounts READ-ONLY (ACCESSPROOF_GATEWAY_EVIDENCE_DIR). The
Gateway serves ``POST /v1/evidence/manifest`` {"source_id": ...} only:
  * in remote exposure (application-authenticated, ap-req-v1 signed, TLS,
    replay-protected, rate-limited, audited like every /v1 route),
  * for ITS OWN tenant and application (cross-tenant requests are refused),
  * after verifying the manifest itself (signature, binding, every chunk
    attestation, expiry); an invalid or expired manifest is never served.
The Gateway holds public keys only; signing keys stay in trusted ingestion.
"""
from __future__ import annotations

import base64
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from packages.rag_core.evidence_manifest import ManifestError, verify_manifest

_SOURCE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


class EvidenceConfigError(RuntimeError):
    pass


def parse_keys(raw: str) -> dict[str, Ed25519PublicKey]:
    try:
        decoded = json.loads(raw)
        if not isinstance(decoded, dict) or not decoded:
            raise ValueError
        return {str(k): Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(str(v) + "=" * (-len(str(v)) % 4)))
                for k, v in decoded.items()}
    except (ValueError, TypeError) as exc:
        raise EvidenceConfigError("invalid manifest public keys") from exc


@dataclass
class EvidenceDistribution:
    root: Path
    manifest_keys: Mapping[str, Ed25519PublicKey]

    @classmethod
    def from_env(cls) -> "EvidenceDistribution | None":
        root = os.getenv("ACCESSPROOF_GATEWAY_EVIDENCE_DIR", "")
        keys = os.getenv("ACCESSPROOF_GATEWAY_EVIDENCE_MANIFEST_KEYS_JSON", "")
        if not root and not keys:
            return None
        if not (root and keys):
            raise EvidenceConfigError("ACCESSPROOF_GATEWAY_EVIDENCE_DIR and _EVIDENCE_MANIFEST_KEYS_JSON go together")
        return cls(Path(root), parse_keys(keys))

    def serve(self, *, tenant_id: str, application_id: str, source_id: str,
              attestation_keys: Mapping[str, Ed25519PublicKey], now: int | None = None) -> tuple[int, bytes | str]:
        if not isinstance(source_id, str) or not _SOURCE.fullmatch(source_id):
            return 400, "SOURCE_ID_INVALID"
        path = self.root / tenant_id / application_id / source_id / "current.json"
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return 404, "EVIDENCE_NOT_PUBLISHED"
        try:
            verify_manifest(json.loads(raw), manifest_keys=self.manifest_keys, attestation_keys=attestation_keys,
                            tenant_id=tenant_id, application_id=application_id, source_id=source_id,
                            now=int(time.time()) if now is None else now)
        except (ManifestError, ValueError, KeyError, TypeError) as exc:
            code = str(exc) if isinstance(exc, ManifestError) else "MANIFEST_INVALID"
            return 503, code
        return 200, raw
