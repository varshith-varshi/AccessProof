"""Operator staging checks are read-only and never expose session credentials."""
from __future__ import annotations

import json
import sys

import pytest

from scripts import validate_google_v1_staging as checker


def test_rejects_http_and_urls_that_embed_credentials(monkeypatch):
    monkeypatch.setenv("ACCESSPROOF_STAGING_SESSION_TOKEN", "synthetic-token")
    for url in (
        "http://staging.example", "https://name:password@staging.example",
        "https://staging.example/redirect", "https://staging.example?token=something",
    ):
        monkeypatch.setattr(sys, "argv", ["check", "--api-url", url, "--organization-id", "org"])
        with pytest.raises(SystemExit, match="2"):
            checker.main()


def test_summarizes_without_printing_source_details(monkeypatch, capsys):
    monkeypatch.setenv("ACCESSPROOF_STAGING_SESSION_TOKEN", "synthetic-session-secret")
    monkeypatch.setattr(sys, "argv", [
        "check", "--api-url", "https://staging.example", "--organization-id", "org",
    ])
    seen = []

    def get_json(url, token, organization_id):
        seen.append((url, token, organization_id))
        if url.endswith("/sources"):
            return 200, [{
                "name": "CONFIDENTIAL CUSTOMER FOLDER", "provider": "google-drive",
                "directory_sync": {"fresh": True}, "acl_sync": {"fresh": False},
                "boundary": "restricted-drive-folder-id",
            }]
        return 200, [{"name": "CONFIDENTIAL GUARD", "health": "healthy"}]

    monkeypatch.setattr(checker, "get_json", get_json)
    assert checker.main() == 0
    text = capsys.readouterr().out
    assert "CONFIDENTIAL" not in text
    assert "restricted-drive-folder-id" not in text
    assert "synthetic-session-secret" not in text
    entries = [json.loads(line) for line in text.splitlines()]
    assert entries[0]["directory_fresh_count"] == 1
    assert entries[0]["acl_fresh_count"] == 0
    assert entries[1]["healthy_count"] == 1
    assert len(seen) == 2


def test_no_direct_session_token_cli_argument(monkeypatch):
    monkeypatch.setenv("ACCESSPROOF_STAGING_SESSION_TOKEN", "synthetic-session-secret")
    monkeypatch.setattr(sys, "argv", [
        "check", "--api-url", "https://staging.example",
        "--organization-id", "org", "--session-token", "should-fail",
    ])
    with pytest.raises(SystemExit, match="2"):
        checker.main()
