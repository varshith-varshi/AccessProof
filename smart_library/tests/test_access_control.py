"""Employee-level (member-level) permission enforcement, identity and fail-closed behaviour."""
from conftest import find

from app.identity import sign


# --- Member-level access: the requester, not the app, decides eligibility -------------------
def test_alice_finance_sees_forecast(client, login):
    assert find(client, login("m-alice"), "b-008") is not None


def test_bob_engineering_cannot_see_forecast(client, login):
    h = login("m-bob")
    assert find(client, h, "b-008") is None
    assert client.get("/books/b-008", headers=h).status_code == 404  # existence not disclosed


def test_carol_hr_sees_hr_policy_only(client, login):
    h = login("m-carol")
    assert find(client, h, "b-010") is not None
    assert find(client, h, "b-008") is None


def test_direct_member_grant(client, login):
    assert find(client, login("m-bob"), "b-011") is not None
    assert find(client, login("m-dave"), "b-011") is None


def test_recommendations_never_leak_restricted_titles(client, login):
    alice = login("m-alice")
    b = find(client, alice, "b-008")
    assert client.post("/books/b-008/checkout", json={"attestation": b["attestation"]}, headers=alice).status_code == 200
    recs = client.get("/me/recommendations?limit=20", headers=login("m-dave")).json()
    assert all(r["collection_id"] in {"general", "research"} for r in recs)


# --- Identity: no email-only trust ----------------------------------------------------------
def test_missing_token_rejected(client):
    assert client.get("/books").status_code == 401


def test_forged_token_rejected(client):
    forged = sign("wrong-secret", {"typ": "member", "sub": "m-alice", "exp": 9e12})
    assert client.get("/books", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_email_as_identity_rejected(client):
    assert client.get("/books", headers={"Authorization": "Bearer alice@library.example"}).status_code == 401


def test_expired_token_rejected(client, login, clock):
    h = login("m-alice")
    clock.advance(3601)
    assert client.get("/books", headers=h).status_code == 401


# --- Layer 2: lineage and tampering -----------------------------------------------------------
def test_checkout_without_attestation_denied(client, login):
    r = client.post("/books/b-001/checkout", json={}, headers=login("m-dave"))
    assert r.status_code == 403 and r.json()["error"] == "missing_attestation"


def test_attestation_of_other_member_denied(client, login):
    alice_att = find(client, login("m-alice"), "b-008")["attestation"]
    r = client.post("/books/b-008/checkout", json={"attestation": alice_att}, headers=login("m-bob"))
    assert r.status_code == 403 and r.json()["error"] == "invalid_attestation"


def test_tampered_attestation_denied(client, login):
    h = login("m-dave")
    att = find(client, h, "b-001")["attestation"]
    body, mac = att.split(".")
    tampered = body[:-2] + ("AA" if body[-2:] != "AA" else "BB") + "." + mac
    r = client.post("/books/b-001/checkout", json={"attestation": tampered}, headers=h)
    assert r.status_code == 403 and r.json()["error"] == "invalid_attestation"


def test_attestation_reused_for_other_book_denied(client, login):
    h = login("m-dave")
    att = find(client, h, "b-001")["attestation"]
    r = client.post("/books/b-003/checkout", json={"attestation": att}, headers=h)
    assert r.status_code == 403 and r.json()["error"] == "invalid_attestation"


def test_attestation_expires(app, client, login, clock):
    h = login("m-dave")
    att = find(client, h, "b-001")["attestation"]
    clock.advance(901)
    app.state.guard.sync()  # keep policy fresh so only the attestation is stale
    h = login("m-dave")
    r = client.post("/books/b-001/checkout", json={"attestation": att}, headers=h)
    assert r.json()["error"] == "attestation_expired"


# --- Revocation ---------------------------------------------------------------------------------
def test_revocation_between_search_and_checkout_blocks_release(client, login):
    alice, libby = login("m-alice"), login("m-libby")
    att = find(client, alice, "b-008")["attestation"]  # Layer 1 allowed
    r = client.request("DELETE", "/admin/memberships", json={"member_id": "m-alice", "group_id": "finance"}, headers=libby)
    assert r.status_code == 200
    r = client.post("/books/b-008/checkout", json={"attestation": att}, headers=alice)
    assert r.status_code == 403 and r.json()["error"] == "access_revoked"
    assert find(client, alice, "b-008") is None  # and Layer 1 now hides it


def test_revocation_without_push_still_caught_by_layer2(app, client, login):
    """Even if the Guard has not yet synced, Layer 2 re-checks the authoritative policy."""
    alice = login("m-alice")
    att = find(client, alice, "b-008")["attestation"]
    app.state.lib.store.remove_membership("m-alice", "finance")  # no guard.sync()
    r = client.post("/books/b-008/checkout", json={"attestation": att}, headers=alice)
    assert r.json()["error"] == "access_revoked"


def test_access_retained_through_another_grant(client, login):
    alice, libby = login("m-alice"), login("m-libby")
    client.post("/admin/grants", json={"collection_id": "finance-reports", "principal_type": "member",
                                       "principal_id": "m-alice"}, headers=libby)
    client.request("DELETE", "/admin/memberships", json={"member_id": "m-alice", "group_id": "finance"}, headers=libby)
    b = find(client, alice, "b-008")
    assert b is not None
    assert client.post("/books/b-008/checkout", json={"attestation": b["attestation"]}, headers=alice).status_code == 200


def test_suspended_member_locked_out(client, login):
    dave, libby = login("m-dave"), login("m-libby")
    client.post("/admin/members/m-dave/suspend", headers=libby)
    assert client.get("/books", headers=dave).status_code == 403


# --- Fail closed ----------------------------------------------------------------------------------
def test_stale_policy_fails_closed(client, login, clock):
    h = login("m-dave")
    clock.advance(601)
    h = login("m-dave")
    r = client.get("/books", headers=h)
    assert r.status_code == 503 and r.json()["error"] == "policy_stale"
    assert client.get("/guard/status").json()["ready"] is False


def test_sync_recovers_after_staleness(app, client, login, clock):
    clock.advance(601)
    app.state.guard.sync()
    assert client.get("/books", headers=login("m-dave")).status_code == 200


def test_guard_unavailable_fails_closed(app, client, login):
    h = login("m-dave")
    app.state.guard.enabled = False
    r = client.get("/books", headers=h)
    assert r.status_code == 503 and r.json()["error"] == "guard_unavailable"


def test_unsupported_release_path_denied(app, login):
    import pytest
    from app.guard import GuardError
    lib = app.state.lib
    att = lib.search("m-dave", "Algorithms")[0]["attestation"]
    with pytest.raises(GuardError) as e:
        app.state.guard.layer2_release("m-dave", lib._raw_book("b-001"), att, "bulk_export")
    assert e.value.code == "unsupported_output_path"


def test_decisions_are_audited(client, login):
    client.post("/books/b-001/checkout", json={}, headers=login("m-dave"))
    log = client.get("/admin/audit", headers=login("m-libby")).json()
    assert any(e["decision"] == "deny" and e["reason"] == "missing_attestation" for e in log)
