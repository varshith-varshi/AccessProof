import json
import httpx
import pytest
from packages.domain.models import Principal, Capability, CapabilityStatus
from packages.test_engine.clock import SimulatedClock
from connectors.mock_source.adapter import MockSourceAdapter
from connectors.microsoft365.adapter import Microsoft365Adapter
from connectors.google_drive.adapter import GoogleDriveAdapter


@pytest.mark.asyncio
async def test_mock_source_common_contract():
    source = MockSourceAdapter(clock=SimulatedClock())
    identity = await source.validate_connection()
    assert identity.boundary == "mock-root"
    caps = await source.discover_capabilities()
    assert caps.supports(Capability.DIRECT_USER_REVOKE)
    r = await source.create_resource(name="AP_TEST", content="secret", marker="AP-CANARY-X")
    alice = Principal("alice")
    await source.grant_access(r, alice)
    assert await source.verify_user_can_access(r, alice)
    await source.revoke_access(r, alice)
    assert not await source.verify_user_can_access(r, alice)
    await source.delete_resource(r)
    assert r.provider_id not in source.resources


@pytest.mark.asyncio
async def test_microsoft_graph_contract_paths():
    permissions = {}

    def handler(req: httpx.Request):
        path = req.url.path
        if req.method == "GET" and path.endswith("/drives/d1/items/root"):
            return httpx.Response(200, json={"id": "root", "name": "AccessProof Test"})
        if req.method == "PUT" and "/drives/d1/items/root:/" in path:
            return httpx.Response(201, json={"id": "file1", "name": "AP_TEST.txt"})
        if req.method == "POST" and path.endswith("/drives/d1/items/file1/invite"):
            permissions["p1"] = "alice@example.com"
            return httpx.Response(200, json={"value": [{"id": "p1"}]})
        if req.method == "GET" and path.endswith("/drives/d1/items/file1/permissions"):
            vals = [
                {"id": pid, "grantedToIdentitiesV2": [{"user": {"email": email}}]}
                for pid, email in permissions.items()
            ]
            return httpx.Response(200, json={"value": vals})
        if req.method == "DELETE" and path.endswith("/permissions/p1"):
            permissions.pop("p1", None)
            return httpx.Response(204)
        if req.method == "DELETE" and path.endswith("/drives/d1/items/file1"):
            return httpx.Response(204)
        return httpx.Response(404, json={"path": path})

    a = Microsoft365Adapter(access_token="token", drive_id="d1", test_root_item_id="root")
    await a._client.aclose()
    a._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), headers={"Authorization": "Bearer token"}
    )
    assert (await a.validate_connection()).boundary == "root"
    r = await a.create_resource(name="AP_TEST", content="x", marker="AP-CANARY")
    alice = Principal("alice", email="alice@example.com")
    assert await a.grant_access(r, alice) == "p1"
    assert await a.verify_user_can_access(r, alice)
    await a.revoke_access(r, alice)
    assert not await a.verify_user_can_access(r, alice)
    await a.delete_resource(r)
    await a._client.aclose()


@pytest.mark.asyncio
async def test_google_drive_contract_paths():
    permissions = {}

    def handler(req: httpx.Request):
        path = req.url.path
        if req.method == "GET" and path.endswith("/drive/v3/files/root"):
            return httpx.Response(
                200, json={"id": "root", "name": "AccessProof", "driveId": "shared1"}
            )
        if req.method == "POST" and path.endswith("/upload/drive/v3/files"):
            return httpx.Response(200, json={"id": "file1", "name": "AP_TEST.txt"})
        if req.method == "POST" and path.endswith("/drive/v3/files/file1/permissions"):
            body = json.loads(req.content.decode())
            permissions["p1"] = body["emailAddress"]
            return httpx.Response(200, json={"id": "p1"})
        if req.method == "GET" and path.endswith("/drive/v3/files/file1/permissions"):
            return httpx.Response(
                200,
                json={
                    "permissions": [
                        {"id": k, "emailAddress": v, "role": "reader", "type": "user"}
                        for k, v in permissions.items()
                    ]
                },
            )
        if req.method == "DELETE" and path.endswith("/drive/v3/files/file1/permissions/p1"):
            permissions.pop("p1", None)
            return httpx.Response(204)
        if req.method == "DELETE" and path.endswith("/drive/v3/files/file1"):
            return httpx.Response(204)
        return httpx.Response(404, json={"path": path})

    a = GoogleDriveAdapter(access_token="token", test_root_folder_id="root")
    await a._client.aclose()
    a._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), headers={"Authorization": "Bearer token"}
    )
    assert (await a.validate_connection()).boundary == "root"
    r = await a.create_resource(name="AP_TEST", content="x", marker="AP-CANARY")
    alice = Principal("alice", email="alice@example.com")
    assert await a.grant_access(r, alice) == "p1"
    assert await a.verify_user_can_access(r, alice)
    await a.revoke_access(r, alice)
    assert not await a.verify_user_can_access(r, alice)
    await a.delete_resource(r)
    await a._client.aclose()


@pytest.mark.asyncio
async def test_confluence_contract_safe_subset():
    from connectors.confluence.adapter import ConfluenceAdapter

    def handler(req: httpx.Request):
        p = req.url.path
        if req.method == "GET" and p.endswith("/wiki/rest/api/space"):
            return httpx.Response(
                200, json={"results": [{"key": "APTEST", "name": "AccessProof Test"}]}
            )
        if req.method == "POST" and p.endswith("/wiki/rest/api/content"):
            return httpx.Response(200, json={"id": "42", "title": "AP_TEST"})
        if req.method == "DELETE" and p.endswith("/wiki/rest/api/content/42"):
            return httpx.Response(204)
        return httpx.Response(404)

    a = ConfluenceAdapter(
        base_url="https://acme.atlassian.net", access_token="t", test_space_key="APTEST"
    )
    await a._client.aclose()
    a._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), headers={"Authorization": "Bearer t"}
    )
    assert (await a.validate_connection()).boundary == "APTEST"
    caps = await a.discover_capabilities()
    assert caps.capabilities[Capability.DIRECT_USER_REVOKE] is CapabilityStatus.EXPERIMENTAL
    assert not caps.supports(Capability.DIRECT_USER_REVOKE)
    r = await a.create_resource(name="AP_TEST", content="x", marker="AP-CANARY")
    await a.delete_resource(r)
    await a._client.aclose()


@pytest.mark.asyncio
async def test_confluence_restriction_revocation_uses_guard_and_effective_permission_check():
    from connectors.confluence.adapter import ConfluenceAdapter

    restrictions: set[str] = set()

    def handler(req: httpx.Request):
        p = req.url.path
        if req.method == "GET" and p.endswith("/wiki/rest/api/space"):
            return httpx.Response(
                200, json={"results": [{"key": "APTEST", "name": "AccessProof Test"}]}
            )
        if req.method == "POST" and p.endswith("/wiki/rest/api/content"):
            return httpx.Response(200, json={"id": "42", "title": "AP_TEST"})
        if p.endswith("/wiki/rest/api/content/42/restriction/byOperation/read/user"):
            account = req.url.params.get("accountId")
            if req.method == "PUT":
                restrictions.add(account)
                return httpx.Response(200, json={})
            if req.method == "DELETE":
                restrictions.discard(account)
                return httpx.Response(200)
        if req.method == "POST" and p.endswith("/wiki/rest/api/content/42/permission/check"):
            body = json.loads(req.content.decode())
            assert body["operation"] == "read"
            account = body["subject"]["identifier"]
            return httpx.Response(200, json={"hasPermission": account in restrictions})
        if req.method == "DELETE" and p.endswith("/wiki/rest/api/content/42"):
            restrictions.clear()
            return httpx.Response(204)
        return httpx.Response(404, json={"method": req.method, "path": p})

    a = ConfluenceAdapter(
        base_url="https://acme.atlassian.net",
        access_token="t",
        test_space_key="APTEST",
        enable_restriction_tests=True,
        restriction_guard_account_id="guard-account",
    )
    await a._client.aclose()
    a._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), headers={"Authorization": "Bearer t"}
    )
    caps = await a.discover_capabilities()
    assert caps.supports(Capability.DIRECT_USER_GRANT)
    assert caps.supports(Capability.DIRECT_USER_REVOKE)
    assert caps.supports(Capability.EFFECTIVE_ACCESS_QUERY)
    r = await a.create_resource(name="AP_TEST", content="x", marker="AP-CANARY")
    alice = Principal("alice-account", email="alice@example.test")
    bob = Principal("bob-account", email="bob@example.test")
    assert await a.grant_access(r, alice) == "alice-account"
    assert restrictions == {"guard-account", "alice-account"}
    assert await a.verify_user_can_access(r, alice) is True
    assert await a.verify_user_can_access(r, bob) is False
    await a.revoke_access(r, alice)
    assert restrictions == {"guard-account"}
    assert await a.verify_user_can_access(r, alice) is False
    await a.delete_resource(r)
    assert restrictions == set()
    await a._client.aclose()


def test_confluence_restriction_mode_requires_guard_identity():
    from connectors.confluence.adapter import ConfluenceAdapter

    with pytest.raises(Exception, match="restriction_guard_account_id"):
        ConfluenceAdapter(
            base_url="https://acme.atlassian.net",
            access_token="t",
            test_space_key="APTEST",
            enable_restriction_tests=True,
        )


@pytest.mark.asyncio
async def test_slack_contract_private_channel_membership():
    from connectors.slack.adapter import SlackAdapter

    members = {"U1"}

    def handler(req: httpx.Request):
        method = req.url.path.rsplit("/", 1)[-1]
        body = json.loads(req.content.decode()) if req.content else {}
        if method == "auth.test":
            return httpx.Response(200, json={"ok": True, "team_id": "T1", "user_id": "BOT"})
        if method == "conversations.info":
            return httpx.Response(
                200,
                json={
                    "ok": True,
                    "channel": {"id": "C1", "name": "accessproof-test", "is_private": True},
                },
            )
        if method == "chat.postMessage":
            return httpx.Response(200, json={"ok": True, "ts": "100.1"})
        if method == "conversations.invite":
            members.add(body["users"])
            return httpx.Response(200, json={"ok": True})
        if method == "conversations.kick":
            members.discard(body["user"])
            return httpx.Response(200, json={"ok": True})
        if method == "chat.delete":
            return httpx.Response(200, json={"ok": True})
        if method == "users.conversations":
            user = req.url.params.get("user")
            return httpx.Response(
                200, json={"ok": True, "channels": [{"id": "C1"}] if user in members else []}
            )
        return httpx.Response(404, json={"ok": False, "error": "unknown"})

    a = SlackAdapter(token="x", test_channel_id="C1")
    await a._client.aclose()
    a._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), headers={"Authorization": "Bearer x"}
    )
    assert (await a.validate_connection()).boundary == "C1"
    r = await a.create_resource(name="AP_TEST", content="x", marker="AP-CANARY")
    u = Principal("U2")
    await a.grant_access(r, u)
    assert await a.verify_user_can_access(r, u)
    await a.revoke_access(r, u)
    assert not await a.verify_user_can_access(r, u)
    await a.delete_resource(r)
    await a._client.aclose()


@pytest.mark.asyncio
async def test_salesforce_contract_safe_subset():
    from connectors.salesforce.adapter import SalesforceAdapter

    created = set()

    def handler(req: httpx.Request):
        p = req.url.path
        if req.method == "GET" and p.endswith("/limits"):
            return httpx.Response(200, json={"DailyApiRequests": {}})
        if req.method == "POST" and "/sobjects/AccessProof_Test__c/" in p:
            created.add("a01000000000000")
            return httpx.Response(201, json={"id": "a01000000000000", "success": True})
        if req.method == "GET" and p.endswith("/query"):
            return httpx.Response(
                200, json={"records": [{"RecordId": "a01000000000000", "HasReadAccess": False}]}
            )
        if req.method == "DELETE" and p.endswith("/sobjects/AccessProof_Test__c/a01000000000000"):
            created.discard("a01000000000000")
            return httpx.Response(204)
        return httpx.Response(404)

    a = SalesforceAdapter(instance_url="https://example.my.salesforce.com", access_token="x")
    await a._client.aclose()
    a._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        headers={"Authorization": "Bearer x", "Content-Type": "application/json"},
    )
    await a.validate_connection()
    caps = await a.discover_capabilities()
    assert caps.supports(Capability.EFFECTIVE_ACCESS_QUERY)
    r = await a.create_resource(name="AP_TEST", content="x", marker="AP-CANARY")
    assert not await a.verify_user_can_access(r, Principal("005000000000001"))
    await a.delete_resource(r)
    await a._client.aclose()


@pytest.mark.asyncio
async def test_microsoft_advanced_test_group_contract_and_effective_access():
    members = set()
    permissions = {}
    root_permissions = {}
    link_permissions = set()
    moved = []

    def handler(req: httpx.Request):
        path = req.url.path
        if req.method == "GET" and path.endswith("/drives/d1/items/root"):
            return httpx.Response(200, json={"id": "root", "name": "AccessProof Test"})
        if req.method == "PUT" and "/drives/d1/items/root:/" in path:
            return httpx.Response(201, json={"id": "file1", "name": "AP_TEST.txt"})
        if req.method == "POST" and path.endswith("/groups/G1/members/$ref"):
            body = json.loads(req.content.decode())
            members.add(body["@odata.id"].rsplit("/", 1)[-1])
            return httpx.Response(204)
        if req.method == "DELETE" and path.endswith("/groups/G1/members/U1/$ref"):
            members.discard("U1")
            return httpx.Response(204)
        if req.method == "POST" and path.endswith("/drives/d1/items/root/invite"):
            body = json.loads(req.content.decode())
            email = body["recipients"][0]["email"]
            root_permissions["parent-p1"] = email
            return httpx.Response(200, json={"value": [{"id": "parent-p1"}]})
        if req.method == "GET" and path.endswith("/drives/d1/items/root/permissions"):
            return httpx.Response(
                200,
                json={
                    "value": [
                        {"id": pid, "grantedToIdentitiesV2": [{"user": {"email": email}}]}
                        for pid, email in root_permissions.items()
                    ]
                },
            )
        if req.method == "DELETE" and path.endswith("/drives/d1/items/root/permissions/parent-p1"):
            root_permissions.pop("parent-p1", None)
            return httpx.Response(204)
        if req.method == "POST" and path.endswith("/drives/d1/items/file1/invite"):
            body = json.loads(req.content.decode())
            email = body["recipients"][0]["email"]
            pid = "gp1" if email == "ap-test-group@example.com" else "p1"
            permissions[pid] = email
            return httpx.Response(200, json={"value": [{"id": pid}]})
        if req.method == "GET" and path.endswith("/drives/d1/items/file1/permissions"):
            vals = []
            for pid, email in permissions.items():
                if pid == "gp1":
                    vals.append(
                        {
                            "id": pid,
                            "grantedToV2": {
                                "group": {"email": email, "displayName": "AccessProof Test Group"}
                            },
                        }
                    )
                else:
                    vals.append({"id": pid, "grantedToIdentitiesV2": [{"user": {"email": email}}]})
            return httpx.Response(200, json={"value": vals})
        if req.method == "POST" and path.endswith("/directoryObjects/U1/checkMemberGroups"):
            body = json.loads(req.content.decode())
            return httpx.Response(
                200,
                json={
                    "value": [gid for gid in body["groupIds"] if gid == "G1" and "U1" in members]
                },
            )
        if req.method == "POST" and path.endswith("/drives/d1/items/file1/createLink"):
            link_permissions.add("link1")
            return httpx.Response(
                201, json={"id": "link1", "link": {"type": "view", "scope": "organization"}}
            )
        if req.method == "DELETE" and path.endswith("/drives/d1/items/file1/permissions/link1"):
            link_permissions.discard("link1")
            return httpx.Response(204, headers={"request-id": "graph-link-revoke-1"})
        if req.method == "PATCH" and path.endswith("/drives/d1/items/file1"):
            body = json.loads(req.content.decode())
            moved.append(body["parentReference"]["id"])
            return httpx.Response(200, json={"id": "file1"})
        if req.method == "DELETE" and path.endswith("/drives/d1/items/file1"):
            return httpx.Response(204)
        return httpx.Response(404, json={"method": req.method, "path": path})

    a = Microsoft365Adapter(
        access_token="token",
        drive_id="d1",
        test_root_item_id="root",
        test_group_id="G1",
        test_group_email="ap-test-group@example.com",
        advanced_directory_mode=True,
        enable_share_link_tests=True,
        move_target_parent_item_id="private-parent",
        enable_parent_acl_tests=True,
    )
    await a._client.aclose()
    a._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), headers={"Authorization": "Bearer token"}
    )

    caps = await a.discover_capabilities()
    assert caps.supports(Capability.GROUP_MEMBER_ADD)
    assert caps.supports(Capability.GROUP_MEMBER_REMOVE)
    assert caps.capabilities[Capability.SHARE_LINK_REVOKE] is CapabilityStatus.SUPPORTED
    assert caps.capabilities[Capability.RESOURCE_MOVE] is CapabilityStatus.SUPPORTED
    assert caps.supports(Capability.PARENT_PERMISSION_MUTATION)

    r = await a.create_resource(name="AP_TEST", content="x", marker="AP-CANARY")
    alice = Principal("U1", email="alice@example.com")
    group_id = await a.create_group(name="ignored-by-safe-provider-adapter")
    assert group_id == "G1"
    await a.add_group_member(group_id, alice)
    await a.grant_group_access(r, group_id)
    assert await a.verify_user_can_access(r, alice)

    await a.remove_group_member(group_id, alice)
    assert not await a.verify_user_can_access(r, alice)

    await a.grant_parent_access(r, alice)
    assert await a.verify_user_can_access(r, alice)
    await a.revoke_parent_access(r, alice)
    assert not await a.verify_user_can_access(r, alice)
    assert not root_permissions

    link_id = await a.create_share_link(r, alice)
    assert link_id == "link1"
    await a.revoke_share_link(r, link_id)
    assert not link_permissions
    assert a.get_last_provider_request_id() == "graph-link-revoke-1"

    await a.move_resource(r)
    assert moved == ["private-parent"]
    await a.delete_resource(r)
    await a._client.aclose()


@pytest.mark.asyncio
async def test_google_drive_parent_acl_and_move_contract():
    root_permissions = {}
    file_parents = {"file1": ["root"]}

    def handler(req: httpx.Request):
        path = req.url.path
        if req.method == "GET" and path.endswith("/drive/v3/files/root"):
            return httpx.Response(
                200,
                json={
                    "id": "root",
                    "name": "AccessProof Root",
                    "driveId": "shared1",
                    "mimeType": "application/vnd.google-apps.folder",
                },
            )
        if req.method == "GET" and path.endswith("/drive/v3/files/private"):
            return httpx.Response(
                200,
                json={
                    "id": "private",
                    "name": "AccessProof Private",
                    "driveId": "shared1",
                    "mimeType": "application/vnd.google-apps.folder",
                },
            )
        if req.method == "POST" and path.endswith("/upload/drive/v3/files"):
            return httpx.Response(
                200, json={"id": "file1", "name": "AP_TEST.txt", "parents": ["root"]}
            )
        if req.method == "POST" and path.endswith("/drive/v3/files/root/permissions"):
            body = json.loads(req.content.decode())
            root_permissions["parent-p1"] = body["emailAddress"]
            return httpx.Response(200, json={"id": "parent-p1"})
        if req.method == "GET" and path.endswith("/drive/v3/files/root/permissions"):
            return httpx.Response(
                200,
                json={
                    "permissions": [
                        {"id": k, "emailAddress": v, "type": "user", "role": "reader"}
                        for k, v in root_permissions.items()
                    ]
                },
            )
        if req.method == "GET" and path.endswith("/drive/v3/files/file1/permissions"):
            return httpx.Response(200, json={"permissions": []})
        if req.method == "GET" and path.endswith("/drive/v3/files/file1"):
            return httpx.Response(200, json={"id": "file1", "parents": file_parents["file1"]})
        if req.method == "PATCH" and path.endswith("/drive/v3/files/file1"):
            assert req.url.params.get("addParents") == "private"
            assert req.url.params.get("removeParents") == "root"
            file_parents["file1"] = ["private"]
            return httpx.Response(
                200,
                json={"id": "file1", "parents": ["private"]},
                headers={"x-request-id": "gdrive-move-1"},
            )
        if req.method == "DELETE" and path.endswith("/drive/v3/files/root/permissions/parent-p1"):
            root_permissions.pop("parent-p1", None)
            return httpx.Response(204)
        if req.method == "DELETE" and path.endswith("/drive/v3/files/file1"):
            return httpx.Response(204)
        return httpx.Response(
            404, json={"method": req.method, "path": path, "query": str(req.url.query)}
        )

    a = GoogleDriveAdapter(
        access_token="token",
        test_root_folder_id="root",
        enable_parent_acl_tests=True,
        move_target_folder_id="private",
    )
    await a._client.aclose()
    a._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), headers={"Authorization": "Bearer token"}
    )
    identity = await a.validate_connection()
    assert identity.boundary == "root"
    caps = await a.discover_capabilities()
    assert caps.supports(Capability.PARENT_PERMISSION_MUTATION)
    assert caps.supports(Capability.RESOURCE_MOVE)
    r = await a.create_resource(name="AP_TEST", content="x", marker="AP-CANARY")
    alice = Principal("U1", email="alice@example.com")
    await a.grant_parent_access(r, alice)
    assert await a.verify_user_can_access(r, alice)
    await a.move_resource(r)
    assert file_parents["file1"] == ["private"]
    assert a.get_last_provider_request_id() == "gdrive-move-1"
    assert not await a.verify_user_can_access(r, alice)
    await a.cleanup()
    assert not root_permissions
    await a.delete_resource(r)
    await a._client.aclose()
