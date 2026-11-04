#!/usr/bin/env python3
"""Lab trusted-ingestion refresher: continuous signed evidence for REMOTE RAGs.

Runs in the TRUSTED-INGESTION environment only, with the existing lab
ingestion (sharepoint-rag-lab ``scripts.live_graph_index_sync.signed_source_payload``:
real Microsoft Graph read, eTag versions, Ed25519 per-chunk attestations with a
30-minute TTL). This script adds:
  * permission fingerprints per item (Graph ``/permissions``, app credentials),
    for change detection only, never authorization;
  * a signed manifest (manifest key in ``~/.ap-id/ingestion``, 0600), published
    atomically into ``--publish-dir`` (mounted read-only into the Gateway);
  * interval + jitter + bounded retries, health file, JSONL event log.

    <lab venv python> scripts/live/evidence_refresher_lab.py --interval 600 [--once]

Prints no tokens, secrets or document content.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
LAB = Path.home() / "Downloads/sharepoint-rag-lab"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(LAB))

import httpx  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from dotenv import dotenv_values  # noqa: E402

from packages.rag_core.evidence_refresher import (EvidencePublisher, EvidenceRefresher, RefreshPolicy,  # noqa: E402
                                                  permissions_fingerprint)

HOME = Path(os.environ.get("AP_INGESTION_HOME", str(Path.home() / ".ap-id/ingestion")))
# Optional customer binding (e.g. a fresh pilot organization with its OWN ingestion key):
# the source is still re-read live every cycle; chunks are re-attested for this binding.
PILOT = {k: os.environ.get(v) for k, v in (("tenant", "AP_BIND_TENANT_ID"), ("app", "AP_BIND_APPLICATION_ID"),
                                          ("source", "AP_BIND_SOURCE_ID"), ("key", "AP_BIND_ATTESTATION_KEY_FILE"),
                                          ("kid", "AP_BIND_ATTESTATION_KEY_ID"))}
CRED = Path.home() / ".config/accessproof/entra-client-secret.json"
SITE = "https://graph.microsoft.com/v1.0/sites/neuralmatrix093.sharepoint.com:/sites/AccessProof-Validation-20261027"


def manifest_key() -> Ed25519PrivateKey:
    HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = HOME / "manifest-signing.key"
    if not path.exists():
        old = os.umask(0o077)
        try:
            path.write_bytes(Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
        finally:
            os.umask(old)
    if path.stat().st_mode & 0o077:
        raise SystemExit("manifest signing key must be 0600")
    return Ed25519PrivateKey.from_private_bytes(path.read_bytes())


def permission_fingerprints(item_ids: list[str]) -> dict[str, str] | None:
    """Per-item permission digests via Graph (app credentials). None = unobservable."""
    from app.graph import SharePointGraph
    conf = dotenv_values(LAB / ".env")
    secret = json.loads(CRED.read_text())
    try:
        with httpx.Client(timeout=20, trust_env=False, follow_redirects=False) as client:
            token = SharePointGraph(conf["SHAREPOINT_TENANT_ID"], secret["client_id"], secret["client_secret"],
                                    drive_id="discovery", client=client)._auth()
            h = {"Authorization": "Bearer " + token}
            site = client.get(SITE, headers=h); site.raise_for_status()
            drives = client.get("https://graph.microsoft.com/v1.0/sites/" + quote(site.json()["id"], safe="") + "/drives", headers=h)
            drives.raise_for_status()
            drive = next(d["id"] for d in drives.json()["value"] if d.get("name") == "Documents")
            out = {}
            for item in item_ids:
                r = client.get(f"https://graph.microsoft.com/v1.0/drives/{drive}/items/{item}/permissions", headers=h)
                r.raise_for_status()
                out[item] = permissions_fingerprint(r.json().get("value", []))
            return out
    except Exception:
        return None


_LAB_MOD = None


def _lab_ingestion():
    """Load the lab's ingestion module by path (the product repo has its own ``scripts`` package)."""
    global _LAB_MOD
    if _LAB_MOD is None:
        import importlib.util
        spec = importlib.util.spec_from_file_location("lab_live_graph_index_sync", LAB / "scripts/live_graph_index_sync.py")
        _LAB_MOD = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_LAB_MOD)
    return _LAB_MOD


def adapter():
    payload = _lab_ingestion().signed_source_payload()   # existing trusted ingestion (reused, unmodified)
    docs = [{"resource_id": d["item_id"], "content_version": d["version"], "name": d["name"]} for d in payload["documents"]]
    chunks = [{"resource_id": c["doc_id"], "chunk_id": c["chunk_id"], "content_version": c["version"],
               "content": c["text"], "content_attestation": c["attestation"]} for c in payload["signed_chunks"]]
    if PILOT["tenant"]:
        from packages.rag_core.attestation import ContentBinding, SourceAttestationSigner
        signer = SourceAttestationSigner(key_id=PILOT["kid"], private_key=_pilot_key())
        for c in chunks:
            c["content_attestation"] = signer.issue(ContentBinding(
                tenant_id=PILOT["tenant"], application_id=PILOT["app"], source_id=PILOT["source"],
                resource_id=c["resource_id"], chunk_id=c["chunk_id"], content_version=c["content_version"],
                content=c["content"]), ttl_seconds=1800)
    return {"documents": docs, "chunks": chunks, "permissions": permission_fingerprints([d["resource_id"] for d in docs])}


def _pilot_key() -> Ed25519PrivateKey:
    path = Path(PILOT["key"])
    if path.stat().st_mode & 0o077:
        raise SystemExit("ingestion signing key must be 0600")
    return Ed25519PrivateKey.from_private_bytes(path.read_bytes())


def build(interval: float, publish_dir: Path) -> EvidenceRefresher:
    conf = dotenv_values(LAB / ".env")
    src_key = serialization.load_pem_private_key((LAB / "secrets/source_signing.pem").read_bytes(), password=None)
    tenant, app_id, source = conf["LAB_TENANT_ID"], conf["LAB_APPLICATION_ID"], conf["LAB_SOURCE_ID"]
    att_keys = {conf["LAB_ATTESTATION_KEY_ID"]: src_key.public_key()}
    if PILOT["tenant"]:
        tenant, app_id, source = PILOT["tenant"], PILOT["app"], PILOT["source"]
        att_keys = {PILOT["kid"]: _pilot_key().public_key()}
    events = HOME / "events.jsonl"

    def on_event(ev: dict) -> None:
        with events.open("a") as fh:
            fh.write(json.dumps(ev) + "\n")
        print(json.dumps(ev), flush=True)
    return EvidenceRefresher(
        adapter=adapter, publisher=EvidencePublisher(publish_dir, tenant, app_id, source),
        tenant_id=tenant, application_id=app_id, source_id=source,
        attestation_keys=att_keys,
        manifest_key=manifest_key(), manifest_key_id="lab-ingestion-manifest-1",
        policy=RefreshPolicy(interval_seconds=interval, attestation_ttl_seconds=1800),
        health_path=HOME / "health.json", on_event=on_event)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--interval", type=float, default=600.0)
    p.add_argument("--publish-dir", default=str(HOME / "published"))
    p.add_argument("--once", action="store_true")
    p.add_argument("--print-public-config", action="store_true")
    a = p.parse_args()
    r = build(a.interval, Path(a.publish_dir))
    if a.print_public_config:
        import base64
        raw = lambda k: base64.urlsafe_b64encode(k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).rstrip(b"=").decode()  # noqa: E731
        print(json.dumps({"tenant_id": r.tenant_id, "application_id": r.application_id, "source_id": r.source_id,
                          "manifest_keys": {r.manifest_key_id: raw(r.manifest_key.public_key())},
                          "attestation_keys": {k: raw(v) for k, v in r.attestation_keys.items()}}))
        return 0
    if a.once:
        return 0 if r.refresh_once()["event"] == "EVIDENCE_REFRESHED" else 1
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    r.run_forever(stop)
    return 0


if __name__ == "__main__":
    sys.exit(main())
