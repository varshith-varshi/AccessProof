"""Core library features: catalogue, loans, renewals, fines, reservations, librarian tools."""
from conftest import find

DAY = 86400


def borrow(client, h, book_id):
    b = find(client, h, book_id)
    return client.post(f"/books/{book_id}/checkout", json={"attestation": b["attestation"]}, headers=h)


def test_search_by_title_author_and_availability(client, login):
    h = login("m-dave")
    assert [b["id"] for b in client.get("/books?q=Austen", headers=h).json()] == ["b-003"]
    assert all(b["category"] == "Fiction" for b in client.get("/books?category=Fiction", headers=h).json())
    borrow(client, h, "b-004")  # single copy
    ids = [b["id"] for b in client.get("/books?available=true", headers=h).json()]
    assert "b-004" not in ids


def test_checkout_and_return_updates_stock(client, login):
    h = login("m-dave")
    r = borrow(client, h, "b-001")
    assert r.status_code == 200
    assert find(client, h, "b-001")["copies_available"] == 2
    loan = client.get("/me/loans", headers=h).json()[0]
    assert loan["overdue"] is False
    assert client.post(f"/loans/{loan['loan_id']}/return", headers=h).json()["fine"] == 0
    assert find(client, h, "b-001")["copies_available"] == 3


def test_cannot_borrow_same_title_twice(client, login):
    h = login("m-dave")
    borrow(client, h, "b-001")
    assert borrow(client, h, "b-001").json()["error"] == "already_borrowed"


def test_loan_limit(client, login):
    h = login("m-bob")
    for bid in ["b-001", "b-002", "b-003", "b-005", "b-006"]:
        assert borrow(client, h, bid).status_code == 200
    assert borrow(client, h, "b-012").json()["error"] == "loan_limit"


def test_overdue_fine_and_block(client, login, clock):
    h = login("m-dave")
    borrow(client, h, "b-001")
    clock.advance(17 * DAY)  # 3 days late
    app_h = login("m-dave")
    client.post("/admin/guard/sync", headers=login("m-libby"))
    assert client.get("/me/loans", headers=app_h).json()[0]["overdue"] is True
    assert borrow(client, app_h, "b-003").json()["error"] == "overdue_items"
    overdue = client.get("/admin/overdue", headers=login("m-libby")).json()
    assert overdue[0]["days_overdue"] == 3 and overdue[0]["fine_so_far"] == 1.5
    loan = client.get("/me/loans", headers=app_h).json()[0]
    assert client.post(f"/loans/{loan['loan_id']}/return", headers=app_h).json()["fine"] == 1.5
    assert client.get("/me", headers=app_h).json()["outstanding_fines"] == 1.5


def test_reservation_queue_holds_returned_copy(client, login):
    dave, bob = login("m-dave"), login("m-bob")
    borrow(client, dave, "b-004")  # the only copy
    b = find(client, bob, "b-004")
    r = client.post("/books/b-004/reserve", json={"attestation": b["attestation"]}, headers=bob)
    assert r.status_code == 200 and r.json()["queue_position"] == 1
    # Renewal is refused while someone waits
    loan = client.get("/me/loans", headers=dave).json()[0]
    att = find(client, dave, "b-004")["attestation"]
    assert client.post(f"/loans/{loan['loan_id']}/renew", json={"attestation": att}, headers=dave).json()["error"] == "reserved"
    assert client.post(f"/loans/{loan['loan_id']}/return", headers=dave).json()["held_for_next_reservation"] is True
    # Copy is held for Bob, not for Carol
    assert borrow(client, login("m-carol"), "b-004").json()["error"] == "held_for_other"
    assert client.get("/me/reservations", headers=bob).json()[0]["status"] == "ready"
    assert borrow(client, bob, "b-004").status_code == 200


def test_reserve_refused_when_available(client, login):
    h = login("m-dave")
    b = find(client, h, "b-001")
    assert client.post("/books/b-001/reserve", json={"attestation": b["attestation"]}, headers=h).json()["error"] == "available"


def test_renew_extends_due_date(client, login):
    h = login("m-dave")
    due = borrow(client, h, "b-001").json()["due_at"]
    loan = client.get("/me/loans", headers=h).json()[0]
    att = find(client, h, "b-001")["attestation"]
    r = client.post(f"/loans/{loan['loan_id']}/renew", json={"attestation": att}, headers=h)
    assert r.json()["due_at"] == due + 14 * DAY


def test_read_digital_edition(client, login):
    h = login("m-dave")
    att = find(client, h, "b-003")["attestation"]
    r = client.post("/books/b-003/read", json={"attestation": att}, headers=h)
    assert r.status_code == 200 and r.json()["content"].startswith("It is a truth")


def test_recommendations_use_borrowing_history(client, login):
    bob, dave = login("m-bob"), login("m-dave")
    borrow(client, bob, "b-001")
    borrow(client, bob, "b-006")
    borrow(client, dave, "b-001")
    recs = [b["id"] for b in client.get("/me/recommendations", headers=dave).json()]
    assert recs[0] == "b-006"  # co-borrowed by a reader with similar history
    assert "b-001" not in recs


def test_admin_requires_librarian(client, login):
    assert client.get("/admin/stats", headers=login("m-dave")).status_code == 403
    stats = client.get("/admin/stats", headers=login("m-libby")).json()
    assert stats["books"] == 12 and stats["members"] == 5


def test_librarian_adds_book(client, login):
    libby = login("m-libby")
    r = client.post("/admin/books", json={"id": "b-100", "isbn": "123", "title": "New Arrivals Guide", "author": "Staff",
                                          "category": "Reference", "collection_id": "general", "copies": 2}, headers=libby)
    assert r.status_code == 201
    assert find(client, login("m-dave"), "b-100")["copies_available"] == 2
