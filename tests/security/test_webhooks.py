from integrations.webhooks.signing import sign_payload, verify_signature


def test_webhook_signature_and_replay_window():
    payload = {"type": "test_run.failed", "run_id": "r1"}
    headers = sign_payload("secret", payload, timestamp=1000)
    assert verify_signature("secret", payload, headers, now=1100)
    assert not verify_signature("secret", payload, headers, now=1401)
    assert not verify_signature("wrong", payload, headers, now=1100)
