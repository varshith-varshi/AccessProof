"""Isolated Microsoft SharePoint -> signed RAG snapshot ingester.

Private signing key and Microsoft Graph app credentials stay in the ingester;
the RAG container consumes only a read-only short-lived signed snapshot.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
from pathlib import Path

from connectors.google_drive.ingest_cli import _private_signer
from connectors.microsoft365.adapter import Microsoft365Adapter
from connectors.microsoft365.trusted_ingestion import SharePointIngestionSettings, SharePointTrustedIngestion
from packages.auth.microsoft_consent import graph_app_token, tenant_uuid
from packages.demo_cache.trusted_snapshot import write_snapshot
from packages.rag_core.ingestion import TrustedSourceIngestor
from packages.rag_core.protection import RetrievedResource

logger = logging.getLogger(__name__)


async def ingest_snapshot(*, access_token: str, tenant_id: str, site_id: str,
                          list_id: str, drive_id: str, root_folder_id: str,
                          application_id: str, source_id: str, signing_key: Path,
                          key_id: str, snapshot_path: Path, max_files: int = 50) -> int:
    if not access_token or any(c in access_token for c in '\r\n'):
        raise ValueError('MICROSOFT_GRAPH_TOKEN_REQUIRED')
    tenant = tenant_uuid(tenant_id)
    if not all((site_id, list_id, drive_id, root_folder_id, application_id, source_id)):
        raise ValueError('MICROSOFT_SOURCE_BINDING_REQUIRED')
    if not 1 <= max_files <= 200:
        raise ValueError('INGESTION_FILE_LIMIT_INVALID')
    adapter = Microsoft365Adapter(
        access_token=access_token, tenant_hint=tenant, drive_id=drive_id,
        test_root_item_id=root_folder_id, sharepoint_site_id=site_id,
        sharepoint_list_id=list_id,
    )
    ingester = None
    try:
        await adapter.validate_connection()
        inventory = await adapter.list_boundary_resources(max_resources=max_files)
        supported = [item for item in inventory if isinstance(item.get('file'), dict)
                     and item['file'].get('mimeType') == 'text/plain']
        if not supported:
            raise ValueError('NO_TRUSTED_SHAREPOINT_TEXT_DOCUMENTS')
        ingester = SharePointTrustedIngestion(
            adapter, TrustedSourceIngestor(_private_signer(signing_key, key_id)),
            SharePointIngestionSettings(
                tenant_id=tenant, application_id=application_id,
                source_id=source_id, max_content_bytes=128_000,
            ),
        )
        resources: list[RetrievedResource] = []
        for item in supported:
            # Atomic snapshot publication: any invalid file fails the entire
            # refresh; never silently publish a partial permission corpus.
            resources.extend(await ingester.ingest(str(item['id'])))
            if len(resources) > 200:
                raise ValueError('TRUSTED_INGESTION_CHUNK_LIMIT')
        if not resources:
            raise ValueError('NO_TRUSTED_SHAREPOINT_CHUNKS')
        write_snapshot(snapshot_path, tenant_id=tenant, application_id=application_id,
                       source_id=source_id, resources=resources)
        return len(resources)
    finally:
        if ingester is not None:
            await ingester.close()
        await adapter._client.aclose()


async def _main(args: argparse.Namespace) -> None:
    if not 30 <= args.interval_seconds <= 240:
        raise ValueError('INVALID_INGESTION_REFRESH_INTERVAL')
    client_id = os.getenv('ACCESSPROOF_MICROSOFT_CLIENT_ID', '').strip()
    client_secret = os.getenv('ACCESSPROOF_MICROSOFT_CLIENT_SECRET', '').strip()
    if not client_id or not client_secret:
        raise ValueError('MICROSOFT_OPERATOR_CREDENTIALS_NOT_CONFIGURED')
    while True:
        try:
            token, _ = await asyncio.to_thread(
                graph_app_token, tenant_id=args.tenant_id,
                client_id=client_id, client_secret=client_secret,
            )
            count = await ingest_snapshot(
                access_token=token, tenant_id=args.tenant_id, site_id=args.site_id,
                list_id=args.list_id, drive_id=args.drive_id,
                root_folder_id=args.root_folder_id, application_id=args.application_id,
                source_id=args.source_id, signing_key=args.private_key,
                key_id=args.key_id, snapshot_path=args.output,
                max_files=args.max_files,
            )
            logger.info('trusted_sharepoint_snapshot_published count=%d', count)
        except Exception as exc:
            # No tokens, provider bodies or document text in logs.
            logger.error('trusted_sharepoint_snapshot_failed code=%s', type(exc).__name__)
            if args.once:
                raise
        if args.once:
            return
        await asyncio.sleep(args.interval_seconds)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    p = argparse.ArgumentParser(description='Isolated SharePoint signed RAG snapshot ingester')
    for name in ('tenant-id', 'site-id', 'list-id', 'drive-id', 'root-folder-id',
                 'application-id', 'source-id', 'key-id'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--private-key', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--max-files', type=int, default=50)
    p.add_argument('--interval-seconds', type=int, default=60)
    p.add_argument('--once', action='store_true')
    asyncio.run(_main(p.parse_args()))


if __name__ == '__main__':
    main()
