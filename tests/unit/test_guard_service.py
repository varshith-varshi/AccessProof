from packages.guard.policy import AccessDecision, AccessMode, AuthorizationPolicy
from packages.guard.service import GuardService, PermissionEvent, Resource


def event(effect, revision, key):
    return PermissionEvent("org-a", "google-drive", "alice-subject", "finance-file", effect, revision, key)


def test_event_pipeline_deduplicates_and_rejects_stale_revisions():
    service = GuardService("org-a", AuthorizationPolicy("policy", 1, AccessMode.PROTECT))
    assert service.ingest(event("allow", 2, "allow-2"))
    assert not service.ingest(event("allow", 2, "allow-2"))
    assert not service.ingest(event("deny", 1, "deny-1"))
    assert service.event_count() == 1
    result = service.filter_resources("alice-subject", "finance-ai", [Resource("g", "finance-file", ("c1", "c2"))])
    assert result.decision == AccessDecision.ALLOW
    assert result.allowed[0].chunk_ids == ("c1", "c2")


def test_protect_layer1_and_layer2_block_denied_provenance():
    service = GuardService("org-a", AuthorizationPolicy("policy", 1, AccessMode.PROTECT))
    service.ingest(event("deny", 3, "deny-3"))
    result = service.filter_resources("alice-subject", "finance-ai", [Resource("g", "finance-file")])
    assert result.decision == AccessDecision.BLOCK
    assert result.allowed == []
    assert service.check_output(result, ["finance-file"]) == AccessDecision.BLOCK


def test_shadow_leaves_context_available_but_records_would_block():
    service = GuardService("org-a", AuthorizationPolicy("policy", 1, AccessMode.SHADOW))
    service.ingest(event("deny", 3, "deny-3"))
    result = service.filter_resources("alice-subject", "finance-ai", [Resource("g", "finance-file")])
    assert result.decision == AccessDecision.WOULD_BLOCK
    # Shadow mode does not alter the customer's retrieval context.
    assert result.denied[0].resource_id == "finance-file"
    assert service.check_output(result, ["finance-file"]) == AccessDecision.WOULD_BLOCK


def test_wrong_tenant_event_is_rejected():
    service = GuardService("org-a", AuthorizationPolicy("policy", 1))
    try:
        service.ingest(PermissionEvent("org-b", "google-drive", "alice", "file", "allow", 1, "x"))
    except ValueError as exc:
        assert str(exc) == "wrong tenant"
    else:
        raise AssertionError("cross-tenant event accepted")
