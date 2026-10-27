"""SharePoint signed RAG bridge: atomic publish, source scoping, tamper denial."""
from __future__ import annotations


import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from connectors.microsoft365 import snapshot_agent
from packages.demo_cache.trusted_snapshot import load_snapshot, SnapshotInvalid
from packages.rag_core import SourceAttestationVerifier

TENANT = '11111111-1111-4111-8111-111111111111'
SITE = 'tenant.sharepoint.com,22222222-2222-4222-8222-222222222222,33333333-3333-4333-8333-333333333333'
LIST = '44444444-4444-4444-8444-444444444444'


@pytest.mark.asyncio
async def test_sharepoint_rag_snapshot_is_signed_bounded_and_loadable(monkeypatch, tmp_path):
    key = Ed25519PrivateKey.generate()
    signing_path = tmp_path / 'key'
    signing_path.write_bytes(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    signing_path.chmod(0o600)
    dest = tmp_path / 'sharepoint.snapshot.json'
    calls = []

    class FakeAdapter:
        def __init__(self, **kwargs):
            calls.append(('adapter', kwargs['test_root_item_id'], kwargs['sharepoint_site_id']))
            self.tenant_hint = kwargs['tenant_hint']
            self.sharepoint_site_id = kwargs['sharepoint_site_id']
            self.sharepoint_list_id = kwargs['sharepoint_list_id']
            self.drive_id = kwargs['drive_id']
            self._client = self

        async def validate_connection(self):
            calls.append(('validated',))

        async def list_boundary_resources(self, *, max_resources):
            calls.append(('inventory', max_resources))
            return [{'id': 'test-file', 'file': {'mimeType': 'text/plain'}}]

        async def aclose(self):
            calls.append(('closed',))

    class FakeIngester:
        def __init__(self, adapter, signer, settings):
            self.signer = signer
            self.settings = settings

        async def ingest(self, item_id):
            from packages.rag_core.ingestion import VerifiedSourceDocument
            calls.append(('ingest', item_id))
            return self.signer.attest_document(VerifiedSourceDocument(
                tenant_id=TENANT, application_id='rag-app', source_id='sharepoint-source',
                resource_id=item_id, content_version='etag-1', content='SYNTHETIC SHAREPOINT CANARY',
                provider_identity_verified=True,
            ))

        async def close(self):
            calls.append(('closed_download',))

    monkeypatch.setattr(snapshot_agent, 'Microsoft365Adapter', FakeAdapter)
    monkeypatch.setattr(snapshot_agent, 'SharePointTrustedIngestion', FakeIngester)
    count = await snapshot_agent.ingest_snapshot(
        access_token='synthetic-app-token', tenant_id=TENANT, site_id=SITE,
        list_id=LIST, drive_id='drive', root_folder_id='approved-folder',
        application_id='rag-app', source_id='sharepoint-source',
        signing_key=signing_path, key_id='test-key', snapshot_path=dest,
    )
    assert count == 1
    assert ('adapter', 'approved-folder', SITE) in calls
    assert calls[-2:] == [('closed_download',), ('closed',)]
    verifier = SourceAttestationVerifier(
        tenant_id=TENANT, trusted_keys={'test-key': key.public_key()}
    )
    retrieved = load_snapshot(dest, verifier=verifier, application_id='rag-app', source_id='sharepoint-source')
    assert retrieved[0].content == 'SYNTHETIC SHAREPOINT CANARY'
    with pytest.raises(SnapshotInvalid):
        load_snapshot(dest, verifier=verifier, application_id='other-rag', source_id='sharepoint-source')
    with pytest.raises(SnapshotInvalid):
        load_snapshot(dest, verifier=verifier, application_id='rag-app', source_id='other-source')
    modified = dest.read_text().replace('SYNTHETIC SHAREPOINT CANARY', 'FORGED SHAREPOINT CANARY')
    dest.write_text(modified)
    with pytest.raises(SnapshotInvalid):
        load_snapshot(dest, verifier=verifier, application_id='rag-app', source_id='sharepoint-source')


@pytest.mark.asyncio
async def test_sharepoint_snapshot_does_not_publish_partial_on_ingestion_failure(monkeypatch, tmp_path):
    key = Ed25519PrivateKey.generate()
    signing_path = tmp_path / 'key'
    signing_path.write_bytes(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    signing_path.chmod(0o600)
    output = tmp_path / 'snap.json'

    class FakeAdapter:
        def __init__(self, **kwargs): self._client = self
        async def validate_connection(self): pass
        async def list_boundary_resources(self, *, max_resources):
            return [{'id': 'good', 'file': {'mimeType': 'text/plain'}},
                    {'id': 'bad', 'file': {'mimeType': 'text/plain'}}]
        async def aclose(self): pass

    class FailingIngester:
        def __init__(self, *args): pass
        async def ingest(self, item_id):
            raise RuntimeError('SIMULATED_PROVIDER_FAILURE')
        async def close(self): pass

    monkeypatch.setattr(snapshot_agent, 'Microsoft365Adapter', FakeAdapter)
    monkeypatch.setattr(snapshot_agent, 'SharePointTrustedIngestion', FailingIngester)
    with pytest.raises(RuntimeError, match='SIMULATED_PROVIDER_FAILURE'):
        await snapshot_agent.ingest_snapshot(
            access_token='synthetic', tenant_id=TENANT, site_id=SITE,
            list_id=LIST, drive_id='drive', root_folder_id='approved-folder',
            application_id='rag-app', source_id='sharepoint-source',
            signing_key=signing_path, key_id='test-key', snapshot_path=output,
        )
    assert not output.exists()
