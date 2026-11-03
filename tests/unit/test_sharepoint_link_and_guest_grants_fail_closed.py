"""SharePoint grants outside the certified scope must never become ALLOW.

Sharing links (anonymous, organization-wide, specific-people), guest or
site-local principals, unknown roles and expired grants are not a named
employee's effective permission. They are excluded by design; these tests pin
that behaviour so a refactor cannot silently widen access.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from apps.api.accessproof_api.acl_sync import _microsoft_permission_authorizes_read, _principal

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)
ALICE = {"user": {"id": "11111111-aaaa-bbbb-cccc-000000000001", "email": "alice@contoso.example"}}
FINANCE = {"group": {"id": "22222222-aaaa-bbbb-cccc-000000000002", "email": "finance@contoso.example"}}


def _perm(**over):
    base = {"id": "p1", "roles": ["read"], "grantedToV2": ALICE}
    base.update(over)
    return base


@pytest.mark.parametrize("scope", ["anonymous", "organization", "users", "existingAccess"])
def test_every_sharing_link_type_is_refused(scope):
    link = _perm(link={"scope": scope, "type": "view", "webUrl": "https://contoso.sharepoint.com/:t:/x"})
    assert _microsoft_permission_authorizes_read(link, NOW) is False
    assert _principal(link, "microsoft365")[0] == "unsupported"


@pytest.mark.parametrize("granted", [
    {"siteUser": {"id": "7", "loginName": "i:0#.f|membership|guest#ext#@contoso.example"}},
    {"user": {"email": "guest@partner.example"}},                 # email only, no directory id
    {"user": {"id": "u"}, "group": {"id": "g"}},                  # ambiguous
    {},
])
def test_guest_site_local_email_only_and_ambiguous_principals_are_refused(granted):
    assert _microsoft_permission_authorizes_read(_perm(grantedToV2=granted), NOW) is False


@pytest.mark.parametrize("roles", [[], ["sp.full control"], ["read", "unknown"], "read", None])
def test_unknown_or_malformed_roles_are_refused(roles):
    assert _microsoft_permission_authorizes_read(_perm(roles=roles), NOW) is False


def test_expired_or_unparseable_expiry_is_refused():
    assert _microsoft_permission_authorizes_read(_perm(expirationDateTime=(NOW - timedelta(seconds=1)).isoformat()), NOW) is False
    assert _microsoft_permission_authorizes_read(_perm(expirationDateTime="soon"), NOW) is False
    assert _microsoft_permission_authorizes_read(_perm(expirationDateTime="2026-12-01T00:00:00"), NOW) is False  # naive


def test_deleted_grant_is_refused():
    assert _microsoft_permission_authorizes_read(_perm(deleted={"state": "deleted"}), NOW) is False


def test_direct_user_and_entra_group_grants_are_the_supported_positive_paths():
    assert _microsoft_permission_authorizes_read(_perm(), NOW) is True
    assert _principal(_perm(), "microsoft365")[:2] == ("subject", ALICE["user"]["id"])
    group = _perm(grantedToV2=FINANCE)
    assert _microsoft_permission_authorizes_read(group, NOW) is True
    assert _principal(group, "microsoft365")[:2] == ("group", FINANCE["group"]["id"])
    future = _perm(expirationDateTime=(NOW + timedelta(days=1)).isoformat())
    assert _microsoft_permission_authorizes_read(future, NOW) is True
