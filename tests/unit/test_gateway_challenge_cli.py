from __future__ import annotations

import json
from pathlib import Path

import pytest

from apps.gateway.accessproof_gateway.challenge_agent import RouteChallengeError
from apps.gateway.accessproof_gateway.challenge_cli import (
    parse_challenge, read_private_json, write_private_result,
)


def _data() -> dict:
    return {
        "url": "http://127.0.0.1:8090/v1/chat/completions",
        "application_id": "reference-app",
        "challenge_nonce": "a" * 40,
        "allowed_canary": "ALLOWED_SAMPLED_RESULT",
        "forbidden_canary": "NEVER_SHARE_PRIVATE",
        "probes": [{
            "name": name, "employee_token": f"synthetic-test-{name}",
            "retrieved_resources": [{"source_id": "drive", "resource_id": "doc"}],
            "expect_status": {
                "allow": [200], "deny": [403],
                "tamper": [503], "layer2_revoke": [403],
            }[name],
        } for name in ("allow", "deny", "tamper", "layer2_revoke")],
    }


def test_cli_parses_only_loopback_restricted_synthetic_challenges() -> None:
    challenge = parse_challenge(_data())
    assert challenge.application_id == "reference-app"
    assert len(challenge.probes) == 4
    with pytest.raises(RouteChallengeError, match="loopback"):
        parse_challenge({**_data(), "url": "http://10.0.0.1:8090/v1/chat/completions"})


def test_cli_rejects_config_injecting_unreviewed_fields() -> None:
    data = _data()
    data["execute"] = "docker stop"
    with pytest.raises(RouteChallengeError, match="Unsupported"):
        parse_challenge(data)


def test_private_input_rejects_world_readable_or_symlink(tmp_path: Path) -> None:
    secret = tmp_path / "synthetic-private.json"
    secret.write_text(json.dumps(_data()))
    secret.chmod(0o644)
    with pytest.raises(RouteChallengeError, match="mode 0600"):
        read_private_json(secret)
    secret.chmod(0o600)
    assert read_private_json(secret)["application_id"] == "reference-app"
    symlink = tmp_path / "link"
    symlink.symlink_to(secret)
    with pytest.raises(RouteChallengeError):
        read_private_json(symlink)


def test_result_written_once_private_with_explicit_no_certification(tmp_path: Path) -> None:
    output = tmp_path / "reference-diagnostic.json"
    write_private_result(output, {
        "status": "PASS_LOCAL_REFERENCE_ONLY",
        "production_certification": False,
        "probes": [],
    })
    assert output.stat().st_mode & 0o777 == 0o600
    assert json.loads(output.read_text())["production_certification"] is False
    with pytest.raises(RouteChallengeError):
        write_private_result(output, {})
    assert json.loads(output.read_text())["production_certification"] is False


def _issued(**overrides) -> dict:
    """Exact field set returned by POST .../protection/challenge."""
    from datetime import datetime, timedelta, timezone
    body = {
        "challenge_id": "chal-1", "nonce": "n" * 54, "guard_id": "guard-1",
        "application_id": "reference-app",
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
        "request_ids": {}, "state": "issued", "production_certification": False,
        "message": "synthetic",
    }
    return {**body, **overrides}


def test_api_challenge_response_was_rejected_directly_and_now_merges() -> None:
    from apps.gateway.accessproof_gateway.challenge_cli import merge_issued_challenge
    config = _data()
    del config["challenge_nonce"]
    with pytest.raises(RouteChallengeError, match="Unsupported"):
        parse_challenge({**config, **_issued()})
    challenge = parse_challenge(merge_issued_challenge(config, _issued()))
    assert challenge.challenge_nonce == "n" * 54


def test_issued_challenge_merge_refuses_mismatch_expiry_and_preset_nonce() -> None:
    from datetime import datetime, timedelta, timezone
    from apps.gateway.accessproof_gateway.challenge_cli import merge_issued_challenge
    config = _data()
    with pytest.raises(RouteChallengeError, match="Remove challenge_nonce"):
        merge_issued_challenge(config, _issued())
    del config["challenge_nonce"]
    with pytest.raises(RouteChallengeError, match="different application"):
        merge_issued_challenge(config, _issued(application_id="other-app"))
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with pytest.raises(RouteChallengeError, match="expired"):
        merge_issued_challenge(config, _issued(expires_at=past))
    with pytest.raises(RouteChallengeError, match="not usable"):
        merge_issued_challenge(config, _issued(state="superseded"))
