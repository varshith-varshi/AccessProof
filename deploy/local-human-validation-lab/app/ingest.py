"""Separate trusted SharePoint ingester. Only this process gets Graph app
credentials and the Ed25519 source signing key.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.graph import SharePointGraph
from app.index import Index, chunks_of


def attestation(key: Ed25519PrivateKey, key_id: str, tenant: str, app: str,
                source: str, doc_id: str, chunk_id: str,
                version: str, text: str, ttl: int = 1800) -> str:
    """Exact AccessProof packages.rag_core.attestation v1 wire contract."""
    now = int(time.time())
    claims = {
        "v": 1, "kid": key_id, "tenant": tenant, "app": app,
        "source": source, "resource": doc_id, "chunk": chunk_id,
        "revision": version, "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "iat": now, "exp": now + ttl,
    }
    payload = json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    token = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
    return token(payload) + "." + token(key.sign(payload))


def sign_and_index(documents, *, index: Index, key: Ed25519PrivateKey, key_id: str,
                   tenant_id: str, app_id: str, source_id: str) -> dict:
    signed = []
    for doc in documents:
        for num, text in enumerate(chunks_of(doc.text)):
            chunk_id = doc.item_id + ":v" + hashlib.sha256(doc.version.encode()).hexdigest()[:12] + ":c" + str(num)
            signed.append({
                "doc_id": doc.item_id, "chunk_id": chunk_id,
                "text": text, "name": doc.name, "url": doc.url,
                "version": doc.version, "attestation": attestation(
                    key, key_id, tenant_id, app_id, source_id, doc.item_id,
                    chunk_id, doc.version, text,
                ),
            })
    return index.replace(documents, signed)


def sync_once() -> dict:
    required = (
        "SHAREPOINT_TENANT_ID", "SHAREPOINT_CLIENT_ID",
        "SHAREPOINT_CLIENT_SECRET", "SHAREPOINT_DRIVE_ID",
        "LAB_SOURCE_SIGNING_KEY_FILE", "LAB_ATTESTATION_KEY_ID",
        "LAB_TENANT_ID", "LAB_APPLICATION_ID", "LAB_SOURCE_ID",
    )
    missing = [name for name in required if not os.getenv(name)]
    if missing:
        raise RuntimeError("MISSING_INGEST_CONFIGURATION: " + ", ".join(missing))
    key_path = Path(os.environ["LAB_SOURCE_SIGNING_KEY_FILE"])
    pem = key_path.read_bytes()
    private = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise RuntimeError("SOURCE_KEY_MUST_BE_ED25519")
    graph = SharePointGraph(
        tenant_id=os.environ["SHAREPOINT_TENANT_ID"],
        client_id=os.environ["SHAREPOINT_CLIENT_ID"],
        client_secret=os.environ["SHAREPOINT_CLIENT_SECRET"],
        drive_id=os.environ["SHAREPOINT_DRIVE_ID"],
        root_item_id=os.getenv("SHAREPOINT_ROOT_ITEM_ID", ""),
        tenant_download_host=os.getenv("SHAREPOINT_DOWNLOAD_HOST", ""),
        max_files=int(os.getenv("LAB_MAX_FILES", "250")),
    )
    documents, skipped = graph.documents()
    index = Index(os.getenv("LAB_INDEX_PATH", "state/index.db"))
    result = sign_and_index(
        documents, index=index, key=private,
        key_id=os.environ["LAB_ATTESTATION_KEY_ID"],
        tenant_id=os.environ["LAB_TENANT_ID"],
        app_id=os.environ["LAB_APPLICATION_ID"],
        source_id=os.environ["LAB_SOURCE_ID"],
    )
    return {**result, "skipped": skipped, "provider": "real_microsoft_graph"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--continuous", action="store_true")
    args = parser.parse_args()
    while True:
        try:
            result = sync_once()
            print(json.dumps(result), flush=True)
        except Exception as exc:
            # Do not print Graph URLs or secret contents. No partial index swap.
            print(json.dumps({"status": "sync_failed", "error": type(exc).__name__,
                              "reason": str(exc) if str(exc).startswith(("GRAPH_", "SHAREPOINT_",
                              "MISSING_", "FILE_", "SOURCE_", "DOCUMENT_")) else "SYNC_UNAVAILABLE"}), flush=True)
            if not args.continuous:
                raise SystemExit(2)
        if not args.continuous:
            break
        time.sleep(max(60, min(int(os.getenv("LAB_SYNC_SECONDS", "300")), 1200)))


if __name__ == "__main__":
    main()
