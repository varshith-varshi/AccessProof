"""Synthetic Microsoft 365 ACL authorization tests (no real provider credentials)."""
from datetime import datetime, timezone

import pytest

from apps.api.accessproof_api.acl_sync import _permission_authorizes_read, _principal


NOW = datetime(2026, 10, 22, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("permission", "expected"),
    [
        ({"id": "p", "roles": ["read"], "grantedToV2": {"user": {"id": "entra-1"}}}, True),
        ({"id": "p", "roles": ["write"], "grantedToV2": {"user": {"id": "entra-1"}}}, True),
        ({"id": "p", "roles": ["owner"], "grantedToV2": {"user": {"id": "entra-1"}}}, True),
        ({"id": "p", "grantedToV2": {"user": {"id": "entra-1"}}}, False),
        ({"id": "p", "roles": ["unknown"], "grantedToV2": {"user": {"id": "entra-1"}}}, False),
        ({"id": "p", "roles": "read", "grantedToV2": {"user": {"id": "entra-1"}}}, False),
        ({"id": "p", "roles": ["read"], "expirationDateTime": "2020-01-01T00:00:00Z", "grantedToV2": {"user": {"id": "entra-1"}}}, False),
        ({"id": "p", "roles": ["read"], "expirationDateTime": "malformed", "grantedToV2": {"user": {"id": "entra-1"}}}, False),
        ({"id": "p", "roles": ["read"], "link": {"scope": "anonymous", "type": "view"}, "grantedToV2": {"user": {"id": "entra-1"}}}, False),
        ({"id": "p", "roles": ["read"], "grantedToV2": {"siteUser": {"id": "42"}}}, False),
        ({"id": "p", "roles": ["read"], "grantedToV2": {"user": {"email": "alice@example.com"}}}, False),
    ],
)
def test_microsoft_only_accepts_supported_readable_permissions(permission, expected):
    assert _permission_authorizes_read(permission, "microsoft365", NOW) is expected


def test_microsoft_principal_uses_stable_directory_id_not_site_id_or_email():
    permission = {"grantedToV2": {
        "siteUser": {"id": "42", "userId": "42", "email": "alice@example.com"},
        "user": {"id": "entra-user-1", "email": "alice@example.com"},
    }}
    assert _principal(permission, "microsoft365") == (
        "subject", "entra-user-1", "alice@example.com"
    )


def test_microsoft_link_or_multiple_grantees_fails_closed():
    assert _principal({
        "link": {"scope": "organization"},
        "grantedToIdentitiesV2": [{"user": {"id": "alice"}}],
    }, "microsoft365")[0] == "unsupported"
    assert _principal({
        "grantedToIdentitiesV2": [
            {"user": {"id": "alice"}}, {"user": {"id": "bob"}},
        ]
    }, "microsoft365")[0] == "unsupported"


def test_other_unrecognized_providers_not_treated_as_microsoft():
    assert _permission_authorizes_read({"id": "p", "roles": ["read"]}, "unknown-system", NOW) is False
    assert _principal({"grantedToV2": {"user": {"id": "somebody"}}}, "unknown-system")[0] == "unsupported"
