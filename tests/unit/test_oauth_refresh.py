from datetime import datetime, timedelta, timezone

import httpx
import pytest

from packages.auth.oauth_refresh import OAuthCredentials, OAuthRefreshError, refresh_credentials


def test_refresh_rotates_token_and_preserves_existing_when_omitted():
    current = OAuthCredentials("old", "refresh-old", datetime.now(timezone.utc) - timedelta(seconds=1))
    saved = []
    client = httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"access_token": "new", "expires_in": 3600})))
    refreshed = refresh_credentials(current, token_endpoint="https://issuer.test/token", client_id="id", client_secret="secret", save=saved.append, client=client)
    assert refreshed.access_token == "new" and refreshed.refresh_token == "refresh-old"
    assert saved == [refreshed]


def test_refresh_classifies_invalid_grant_without_exposing_provider_body():
    client = httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(400, json={"error": "invalid_grant", "error_description": "sensitive"})))
    with pytest.raises(OAuthRefreshError, match="REAUTHORIZATION_REQUIRED"):
        refresh_credentials(OAuthCredentials("old", "refresh"), token_endpoint="https://issuer.test/token", client_id="id", client_secret="secret", save=lambda _: None, client=client)
