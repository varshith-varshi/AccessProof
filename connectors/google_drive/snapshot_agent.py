"""Dedicated customer-side Google Drive -> signed snapshot ingestion agent.

This process owns the source signing key; the RAG runtime and model never do.
It runs in a separate container with an isolated read/write snapshot volume.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
from pathlib import Path

from packages.auth.google_source_token import GoogleSourceTokenStore
from connectors.google_drive.adapter import GoogleDriveAdapter
from connectors.google_drive.ingest_cli import _private_signer
from connectors.google_drive.trusted_ingestion import (
    GoogleDriveIngestionSettings, GoogleDriveTrustedIngestion,
)
from packages.demo_cache.trusted_snapshot import write_snapshot
from packages.rag_sdk.ingestion import TrustedSourceIngestor
from packages.rag_sdk.protection import RetrievedResource

logger = logging.getLogger(__name__)


async def ingest_snapshot(*, access_token: str, root_folder_id: str,
                          tenant_id: str, application_id: str, source_id: str,
                          signing_key: Path, key_id: str, snapshot_path: Path,
                          max_files: int = 50) -> int:
    if not all((access_token, root_folder_id, tenant_id, application_id, source_id, key_id)):
        raise ValueError("TRUSTED_INGESTION_CONFIGURATION_INCOMPLETE")
    if not 1 <= max_files <= 200:
        raise ValueError("TRUSTED_INGESTION_FILE_LIMIT_INVALID")
    signer = _private_signer(signing_key, key_id)
    adapter = GoogleDriveAdapter(
        access_token=access_token, test_root_folder_id=root_folder_id,
    )
    try:
        await adapter.validate_connection()
        # Inventory is bounded and root-scoped. Unsupported formats, including
        # native Docs and shortcuts, are not silently reinterpreted as text.
        items = await adapter.list_boundary_resources(max_items=max_files)
        supported = [
            item for item in items
            if item.get("mimeType") in {
                "text/plain", "application/vnd.google-apps.document",
            }
        ]
        ingester = GoogleDriveTrustedIngestion(
            adapter, TrustedSourceIngestor(signer),
            GoogleDriveIngestionSettings(
                tenant_id=tenant_id, application_id=application_id, source_id=source_id,
                max_content_bytes=128_000,
            ),
        )
        resources: list[RetrievedResource] = []
        for item in supported:
            # Any provider failure aborts the entire snapshot. Never publish
            # a partially refreshed index as complete.
            resources.extend(await ingester.ingest(str(item["id"])))
            if len(resources) > 200:
                raise ValueError("TRUSTED_INGESTION_CHUNK_LIMIT")
        # Empty root is non-certifiable; avoid replacing last known trusted
        # snapshot with an unsafe/incomplete inventory.
        if not resources:
            raise ValueError("NO_TRUSTED_TEXT_DOCUMENTS")
        write_snapshot(
            snapshot_path, tenant_id=tenant_id, application_id=application_id,
            source_id=source_id, resources=resources,
        )
        return len(resources)
    finally:
        await adapter._client.aclose()


async def _main(args: argparse.Namespace) -> None:
    # Source credentials belong in this ingester container only. The demo
    # RAG container gets no provider credential in signed-snapshot mode.
    token_store_path = os.getenv("ACCESSPROOF_GOOGLE_DRIVE_CREDENTIALS_FILE", "").strip()
    token_store = GoogleSourceTokenStore(Path(token_store_path)) if token_store_path else None
    static_token = os.getenv("ACCESSPROOF_GOOGLE_DRIVE_ACCESS_TOKEN", "").strip()
    if token_store is None and not static_token:
        raise ValueError("INGESTION_GOOGLE_TOKEN_REQUIRED")
    if not 30 <= args.interval_seconds <= 240:
        raise ValueError("INVALID_INGESTION_REFRESH_INTERVAL")
    while True:
        try:
            token = (await asyncio.to_thread(token_store.access_token)
                     if token_store is not None else static_token)
            count = await ingest_snapshot(
                access_token=token, root_folder_id=args.root_folder_id,
                tenant_id=args.tenant_id, application_id=args.application_id,
                source_id=args.source_id, signing_key=args.private_key,
                key_id=args.key_id, snapshot_path=args.output,
                max_files=args.max_files,
            )
            logger.info("trusted_drive_snapshot_published count=%d", count)
        except Exception as exc:
            # No fallback to previously unsigned ingestion or unverified docs.
            # Existing snapshot attestations expire automatically.
            logger.error("trusted_drive_snapshot_failed code=%s", type(exc).__name__)
            if args.once:
                raise
        if args.once:
            return
        await asyncio.sleep(args.interval_seconds)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="Customer-side signed Drive snapshot ingester")
    parser.add_argument("--root-folder-id", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--application-id", required=True)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-files", type=int, default=50)
    parser.add_argument("--interval-seconds", type=int, default=60)
    parser.add_argument("--once", action="store_true")
    asyncio.run(_main(parser.parse_args()))


if __name__ == "__main__":
    main()
