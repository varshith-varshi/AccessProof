"""Read-only independent watcher never certifies, imports or signs anything."""
from datetime import datetime, timezone

import pytest
from scripts.certifier import independent_status_watcher as w

NOW = datetime(2026,11,8,6,0,tzinfo=timezone.utc)


def test_source_status_and_renewal_windows():
    epoch=NOW.timestamp()+20*86400
    x=w.parse_source(f"{epoch}|verified",NOW.timestamp())
    assert x["state"]=="VALID" and x["renewal_window"] is False
    x=w.parse_source(f"{NOW.timestamp()+86400}|verified",NOW.timestamp())
    assert x["renewal_window"] is True
    assert w.parse_source(f"{epoch}|unverified",NOW.timestamp())["state"]=="UNVERIFIED"
    assert w.parse_source("nonsense",NOW.timestamp())["state"]=="UNOBSERVABLE"


def test_route_status_counts_current_vs_history():
    raw='{"certified":true,"routes":[{"state":"VALID","expires_at":"2026-11-11T06:00:00+00:00"},{"state":"INVALIDATED","expires_at":"2026-11-09T06:00:00+00:00"}]}'
    x=w.parse_routes(raw,NOW)
    assert x["state"]=="CERTIFIED"
    assert x["valid_route_count"]==1
    assert x["historically_invalidated_count"]==1
    assert x["earliest_valid_expiry_days"]==3
    assert not x["renewal_window"]
    assert w.parse_routes('{"certified":true,"routes":[]}',NOW)["state"]=="NOT_CERTIFIED"
    assert w.parse_routes('not json',NOW)["state"]=="UNOBSERVABLE"


def test_only_named_readonly_operations_are_allowed(monkeypatch):
    calls=[]
    monkeypatch.setattr(w,"aws",lambda *a: calls.append(a))
    with pytest.raises(ValueError):
        w.read_only("route_certificate_import",organization_id=w.ORG)
    with pytest.raises(ValueError):
        w.read_only("certificate_status",organization_id="wrong",source_id=w.SOURCE)
    with pytest.raises(ValueError):
        w.read_only("route_status",organization_id=w.ORG,application_id="wrong")
    assert not calls


def test_ssm_invocation_uses_pinned_document_and_instance(monkeypatch):
    seen=[]
    def fake_aws(*args):
        seen.append(args)
        if args[1]=="send-command":
            return {"Command":{"CommandId":"synthetic"}}
        return {"Status":"Success","ResponseCode":0,"StandardOutputContent":"123|verified"}
    monkeypatch.setattr(w,"aws",fake_aws)
    monkeypatch.setattr(w.time,"sleep",lambda _:None)
    assert w.read_only("certificate_status",organization_id=w.ORG,source_id=w.SOURCE)=="123|verified"
    assert w.DOC in seen[0] and w.PRODUCTION in seen[0]
    assert seen[1][1]=="get-command-invocation"
    assert not any("AWS-RunShellScript" in str(x) for x in seen)


def test_watch_never_claims_renewal_independence(monkeypatch):
    monkeypatch.setattr(w.hp,"report",lambda **kwargs:{"host_prerequisites":"PASS"})
    monkeypatch.setattr(w,"read_only",lambda op,**kw:
                        f"{NOW.timestamp()+15*86400}|verified" if op=="certificate_status"
                        else '{"certified":true,"routes":[{"state":"VALID","expires_at":"2026-11-11T06:00:00+00:00"}]}')
    data=w.watch(instance="i-0123456789abcdef0",role_arn="role",key_arn="key")
    assert data["monitor_status"]=="UP"
    assert data["renewal_independent"] is False and data["signing_enabled"] is False


def test_wrong_host_prevents_all_production_calls(monkeypatch):
    monkeypatch.setattr(w.hp,"report",lambda **kwargs:{"host_prerequisites":"BLOCKED"})
    monkeypatch.setattr(w,"read_only",lambda *a,**k: (_ for _ in ()).throw(AssertionError("SSM call")))
    with pytest.raises(RuntimeError,match="HOST_IDENTITY_KMS"):
        w.watch(instance="i-0123456789abcdef0",role_arn="role",key_arn="key")


def test_kms_signing_and_production_import_not_permitted_in_template():
    import json
    from pathlib import Path
    t=json.loads((Path(__file__).resolve().parents[2]/"deploy/certifier/independent/isolated-certifier-stack.json").read_text())
    statements=[s for policy in t["Resources"]["CertifierExecutionRole"]["Properties"]["Policies"]
                for s in policy["PolicyDocument"]["Statement"]]
    assert not any("kms:Sign" in json.dumps(s) or "ProductionImport" in json.dumps(s) for s in statements)
    allowed=[s for s in statements if s.get("Sid")=="OnlyFixedReadOnlyDocumentOnPinnedProductionInstance"]
    assert len(allowed)==1
    assert allowed[0]["Action"]=="ssm:SendCommand"
    assert len(allowed[0]["Resource"])==2
