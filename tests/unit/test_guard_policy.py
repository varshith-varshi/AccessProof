from packages.guard.permissions import EffectiveAccessResolver, PermissionGrant, PermissionSnapshot
from packages.guard.policy import AccessDecision, AccessMode, AuthorizationPolicy, Guard
from packages.guard.parallel import bounded_map


def test_overlapping_group_grants_remain_allowed_until_last_grant_removed():
    grants = [
        PermissionGrant("alice", "finance", group_id="finance-readers"),
        PermissionGrant("alice", "finance", group_id="finance-managers"),
    ]
    resolver = EffectiveAccessResolver(PermissionSnapshot(grants=grants))
    assert resolver.allowed("alice", "finance")
    resolver.snapshot.grants.pop(0)
    assert resolver.allowed("alice", "finance")
    resolver.snapshot.grants.pop(0)
    assert not resolver.allowed("alice", "finance")


def test_shadow_records_would_block_without_changing_rag_result():
    guard = Guard(EffectiveAccessResolver(PermissionSnapshot()), AuthorizationPolicy("p", 1, AccessMode.SHADOW))
    decision, denied = guard.authorize(subject_id="alice", application_id="rag", resource_ids=["finance"])
    assert decision == AccessDecision.WOULD_BLOCK
    assert denied == ["finance"]
    assert guard.audit[0]["reason"] == "effective_access_denied"


def test_protect_batches_resources_and_blocks_before_generation():
    resolver = EffectiveAccessResolver(PermissionSnapshot([PermissionGrant("alice", "public")]))
    guard = Guard(resolver, AuthorizationPolicy("p", 2, AccessMode.PROTECT))
    decision, denied = guard.authorize(subject_id="alice", application_id="rag", resource_ids=["public", "secret"])
    assert decision == AccessDecision.BLOCK
    assert denied == ["secret"]


def test_bounded_map_isolates_failures_and_preserves_order():
    def work(value):
        if value == 3:
            raise RuntimeError("provider failure")
        return value * 2
    results = bounded_map(range(10), work, max_workers=3)
    assert results[:3] == [0, 2, 4]
    assert isinstance(results[3], RuntimeError)
    assert results[4:] == [8, 10, 12, 14, 16, 18]
