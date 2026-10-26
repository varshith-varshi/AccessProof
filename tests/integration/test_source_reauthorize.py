from types import SimpleNamespace

from fastapi.testclient import TestClient

from apps.api.accessproof_api import app as app_module
from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, SourceConnection, engine, SessionLocal


class _Candidate:
    async def validate_connection(self):
        return SimpleNamespace(provider="demo", tenant="tenant", account="account", boundary="boundary", metadata={})
    async def discover_capabilities(self):
        from packages.connector_sdk.base import CapabilityReport
        from packages.domain.models import Capability, CapabilityStatus
        return CapabilityReport({cap: CapabilityStatus.SUPPORTED for cap in Capability})


def test_reauthorize_requires_new_credentials_and_preserves_old_on_failed_validation(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        signup=client.post("/api/v1/auth/signup",json={"email":"reauth@example.com","password":"correct horse battery staple","organization_name":"Reauth"}).json()
        headers={"Authorization":f"Bearer {signup['session_token']}","X-Organization-ID":signup["organization_id"]}
        project=client.post("/api/v1/projects",headers=headers,json={"name":"Pilot"}).json()["id"]
        source=client.post("/api/v1/sources",headers=headers,json={"project_id":project,"provider":"demo-ai","name":"Demo","boundary":"demo","credentials":{"base_url":"http://old","service_token":"old-secret"},"mutation_acknowledged":True}).json()["id"]
        assert client.post(f"/api/v1/sources/{source}/reauthorize",headers=headers,json={"credentials":{}}).status_code==422
        monkeypatch.setattr(app_module,"create_source_adapter",lambda *_args,**_kwargs: (_ for _ in ()).throw(ValueError("bad credential")))
        failed=client.post(f"/api/v1/sources/{source}/reauthorize",headers=headers,json={"credentials":{"base_url":"http://bad","service_token":"new-secret"}})
        assert failed.status_code==422 and "new-secret" not in failed.text
        with SessionLocal() as db:
            old=db.get(SourceConnection,source).encrypted_credentials
            assert "old-secret" not in old
        monkeypatch.setattr(app_module,"create_source_adapter",lambda *_args,**_kwargs:_Candidate())
        good=client.post(f"/api/v1/sources/{source}/reauthorize",headers=headers,json={"credentials":{"base_url":"http://new","service_token":"new-secret"}})
        assert good.status_code==200 and "new-secret" not in good.text
        with SessionLocal() as db:
            encrypted=db.get(SourceConnection,source).encrypted_credentials
            assert encrypted!=old and "new-secret" not in encrypted
