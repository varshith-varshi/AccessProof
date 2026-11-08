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


def test_independent_routes_are_not_equivalent_to_app_certificate_or_gateway_presence():
    from datetime import timedelta
    import json
    expiry = (NOW + timedelta(hours=18)).isoformat()
    remote = {"certified": True, "routes": [{"state": "VALID", "expires_at":
             (NOW + timedelta(days=4)).isoformat()}]}
    older = w.parse_routes(json.dumps(remote), NOW)
    assert older["state"] == "CERTIFIED"
    assert older["application_route"]["state"] == "UNOBSERVABLE"
    assert older["gateway"]["state"] == "UNOBSERVABLE"
    remote["application_route_certificate"] = {
        "status": "CERTIFIED", "certified": True, "expires_at": expiry,
    }
    remote["gateway_presence"] = {
        "connection": "DISCONNECTED", "enforcement_ready_reported": False, "reason": "HEARTBEAT_EXPIRED",
    }
    disconnected = w.parse_routes(json.dumps(remote), NOW)
    assert disconnected["application_route"]["state"] == "CERTIFIED"
    assert disconnected["gateway"]["state"] == "NOT_READY"
    remote["gateway_presence"].update(connection="CONNECTED", enforcement_ready_reported=True)
    ready = w.parse_routes(json.dumps(remote), NOW)
    assert ready["gateway"]["state"] == "READY"
    assert ready["application_route"]["renewal_window"] is False
    remote["application_route_certificate"]["expires_at"] = (NOW - timedelta(hours=1)).isoformat()
    expired = w.parse_routes(json.dumps(remote), NOW)
    assert expired["application_route"]["state"] == "EXPIRED"
    remote["application_route_certificate"]["expires_at"] = "2026-11-08T08:00:00"  # timezone ambiguous
    assert w.parse_routes(json.dumps(remote), NOW)["state"] == "UNOBSERVABLE"


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
    pilot = w.MONITORED["pilot"]
    assert w.read_only("route_status", organization_id=pilot["organization_id"],
                       application_id=pilot["application_id"]) == "123|verified"
    assert w.DOC in seen[2] and w.PRODUCTION in seen[2]
    with pytest.raises(ValueError, match="SOURCE_BINDING_INVALID"):
        w.read_only("certificate_status", organization_id=pilot["organization_id"],
                    source_id=w.SOURCE)
    with pytest.raises(ValueError, match="APP_BINDING_INVALID"):
        w.read_only("route_status", organization_id=w.ORG, application_id=pilot["application_id"])
    assert not any("AWS-RunShellScript" in str(x) for x in seen)


def test_watch_never_claims_renewal_independence(monkeypatch):
    monkeypatch.setattr(w.hp,"report",lambda **kwargs:{"host_prerequisites":"PASS"})
    app_expiry = datetime.now(timezone.utc).timestamp() + 18 * 3600
    app_expiry_utc = datetime.fromtimestamp(app_expiry, tz=timezone.utc).isoformat()
    healthy_route = '{"certified":true,"routes":[{"state":"VALID","expires_at":"2026-11-15T06:00:00+00:00"}], "application_route_certificate":{"certified":true,"status":"CERTIFIED","expires_at":"' + app_expiry_utc + '"},"gateway_presence":{"connection":"CONNECTED","enforcement_ready_reported":true}}'
    monkeypatch.setattr(w,"read_only",lambda op,**kw:
                        f"{datetime.now(timezone.utc).timestamp()+15*86400}|verified" if op=="certificate_status"
                        else healthy_route)
    data=w.watch(instance="i-0123456789abcdef0",role_arn="role",key_arn="key")
    assert data["monitor_status"]=="UP"
    assert data["monitored_scope_count"] == 2
    assert set(data["scopes"]) == {"pilot", "reference"}
    assert all(x["certification_healthy"] for x in data["scopes"].values())
    assert data["renewal_independent"] is False and data["signing_enabled"] is False


def test_unhealthy_or_missing_pilot_is_visible_and_degrades_monitor(monkeypatch):
    monkeypatch.setattr(w.hp, "report", lambda **kwargs: {"host_prerequisites": "PASS"})
    observed = []

    def mocked_read_only(operation, **params):
        observed.append((operation, params))
        pilot = params["organization_id"] == w.MONITORED["pilot"]["organization_id"]
        if pilot and operation == "route_status":
            raise RuntimeError("SSM_ACCESS_DENIED")
        if operation == "certificate_status":
            return f"{datetime.now(timezone.utc).timestamp()+10*86400}|verified"
        return '{"certified":true,"routes":[{"state":"VALID","expires_at":"2026-11-14T06:00:00+00:00"}]}'

    monkeypatch.setattr(w, "read_only", mocked_read_only)
    result = w.watch(instance="i-0123456789abcdef0", role_arn="role", key_arn="key")
    assert len(observed) == 4
    assert result["monitor_status"] == "DEGRADED"
    assert result["scopes"]["pilot"]["routes"]["state"] == "UNOBSERVABLE"
    assert result["scopes"]["pilot"]["certification_healthy"] is False
    assert result["scopes"]["reference"]["source"]["state"] == "VALID"


def test_unverified_source_fails_monitor_even_if_routes_valid(monkeypatch):
    monkeypatch.setattr(w.hp, "report", lambda **kwargs: {"host_prerequisites": "PASS"})
    monkeypatch.setattr(w, "read_only", lambda op, **params:
                        f"{datetime.now(timezone.utc).timestamp()+86400}|unverified"
                        if op == "certificate_status" else
                        '{"certified":true,"routes":[{"state":"VALID","expires_at":"2026-11-14T06:00:00+00:00"}]}')
    data = w.watch(instance="i-0123456789abcdef0", role_arn="role", key_arn="key")
    assert data["monitor_status"] == "DEGRADED"
    assert not any(x["certification_healthy"] for x in data["scopes"].values())


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
