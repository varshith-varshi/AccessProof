"""A revocation installed at the response gate must not release old content."""
from datetime import datetime, timedelta, timezone

import jwt
from fastapi.testclient import TestClient

from apps.guard.accessproof_guard import app as guard_app
from apps.guard.accessproof_guard.cache import PolicyCache


def test_policy_rollover_during_layer2_consumption_blocks_release(tmp_path, monkeypatch):
    policy = PolicyCache(str(tmp_path / "version-race.db"))
    policy.install(1, [{
        "subject_id": "alice", "source_id": "drive",
        "resource_id": "finance", "decision": "allow",
    }])
    policy.set_application_bindings([{
        "application_id": "rag", "source_id": "drive", "mode": "protect",
        "source_acl_healthy": True,
    }])
    policy.mark_sync_success()
    secret = "synthetic-release-race-key-over-32-characters"
    settings = {
        "cache": policy, "identity_mode": "static", "issuer": "https://id.local",
        "audience": "rag", "verification_key": secret,
        "subject_claim": "sub", "expected_tenant": None,
        "max_policy_age_seconds": 300,
    }
    for key, value in settings.items():
        monkeypatch.setattr(guard_app, key, value)
    token = jwt.encode({
        "sub": "alice", "iss": "https://id.local", "aud": "rag",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }, secret, algorithm="HS256")
    headers = {"Authorization": f"Bearer {token}"}

    def filter_request(client, request_id):
        result = client.post("/guard/v1/filter-resources", headers=headers, json={
            "application_id": "rag", "request_id": request_id,
            "resources": [{"source_id": "drive", "resource_id": "finance"}],
        })
        assert result.status_code == 200
        return result.json()

    def output_request(client, request_id, decision_id):
        return client.post("/guard/v1/check-output", headers=headers, json={
            "application_id": "rag", "request_id": request_id,
            "decision_id": decision_id, "used_resource_ids": ["finance"],
            "provenance": [{"source_resource_ids": ["finance"]}],
        })

    with TestClient(guard_app.app) as client:
        first = filter_request(client, "race-1")
        assert first["decision"] == "allow"
        original_consume = policy.consume_contexts_with_recheck

        def revoke_before_context_consumption(*args, **kwargs):
            policy.install(2, [{
                "subject_id": "alice", "source_id": "drive",
                "resource_id": "finance", "decision": "deny", "reason": "REVOKED",
            }])
            return original_consume(*args, **kwargs)

        monkeypatch.setattr(policy, "consume_contexts_with_recheck", revoke_before_context_consumption)
        denied = output_request(client, "race-1", first["decision_id"])
        assert denied.status_code == 200
        assert denied.json()["decision"] == "block", denied.json()

        # Paired positive control: a new, stable grant still completes both layers.
        monkeypatch.setattr(policy, "consume_contexts_with_recheck", original_consume)
        policy.install(3, [{
            "subject_id": "alice", "source_id": "drive",
            "resource_id": "finance", "decision": "allow",
        }])
        second = filter_request(client, "stable-allow")
        assert second["decision"] == "allow"
        allowed = output_request(client, "stable-allow", second["decision_id"])
        assert allowed.status_code == 200
        assert allowed.json()["decision"] == "allow"
