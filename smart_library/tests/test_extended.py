"""Tests for the extended website API: demo data, catalogue, member views, librarian tools,
migrations, append-only audit, the public landing data and SPA/API routing."""
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.clock import Clock
from app.config import Settings
from app.db import SCHEMA, Database
from app.demo_data import load_demo_data
from app.main import create_app
from app.seed import seed

DAY = 86400
RESTRICTED = {"finance-reports", "hr-records", "rare-books"}


@pytest.fixture()
def demo(tmp_path):
    clock = Clock(start=1_800_000_000.0)
    settings = Settings(db_path=str(tmp_path / "demo.db"), secret_key="test-secret", demo_data=True)
    app = create_app(settings, clock, background_sync=False)
    with TestClient(app) as c:
        def login(member_id):
            r = c.post("/auth/demo-login", json={"member_id": member_id})
            return {"Authorization": f"Bearer {r.json()['access_token']}"}
        yield app, c, login, clock


def att(c, h, book_id):
    r = c.get(f"/books/{book_id}", headers=h)
    return r.json()["attestation"] if r.status_code == 200 else None


# --- database ---------------------------------------------------------------------------------
def test_migration_upgrades_old_schema_without_losing_rows(tmp_path):
    path = str(tmp_path / "old.db")
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)  # the original 10-table schema
    conn.execute("INSERT INTO collections (id, name) VALUES ('general', 'General')")
    conn.execute("INSERT INTO books (id, isbn, title, author, category, collection_id) VALUES"
                 " ('x', '1', 'Kept', 'A', 'C', 'general')")
    conn.commit()
    conn.close()
    db = Database(path)
    Database(path)  # idempotent
    row = db.one("SELECT * FROM books WHERE id = 'x'")
    assert row["title"] == "Kept" and row["description"] == "" and "cover_url" in row.keys()
    assert "renewals" in {r["name"] for r in db.query("PRAGMA table_info(loans)")}
    assert db.one("SELECT 1 FROM sqlite_master WHERE name = 'app_meta'") is not None


def test_audit_log_is_append_only(tmp_path):
    db = Database(str(tmp_path / "a.db"))
    with db.tx() as c:
        c.execute("INSERT INTO audit_log (at, action, decision, reason) VALUES (1, 'x', 'info', 'r')")
    with pytest.raises(sqlite3.IntegrityError):
        with db.tx() as c:
            c.execute("UPDATE audit_log SET decision = 'allow'")
    with pytest.raises(sqlite3.IntegrityError):
        with db.tx() as c:
            c.execute("DELETE FROM audit_log")


def test_demo_data_is_safe_to_rerun(tmp_path):
    db = Database(str(tmp_path / "d.db"))
    seed(db)
    with db.tx() as c:
        c.execute("UPDATE books SET description = 'my own text' WHERE id = 'b-001'")
    load_demo_data(db, 1_800_000_000.0)
    counts = [db.one(f"SELECT COUNT(*) AS n FROM {t}")["n"] for t in ("books", "members", "loans", "reservations")]
    load_demo_data(db, 1_800_000_000.0)
    assert counts == [db.one(f"SELECT COUNT(*) AS n FROM {t}")["n"] for t in ("books", "members", "loans", "reservations")]
    assert counts[0] == 40
    assert db.one("SELECT description FROM books WHERE id = 'b-001'")["description"] == "my own text"


def test_demo_stock_is_consistent(demo):
    app, *_ = demo
    db = app.state.lib.db
    for b in db.query("SELECT * FROM books"):
        on_loan = db.one("SELECT COUNT(*) AS n FROM loans WHERE book_id = ? AND returned_at IS NULL", (b["id"],))["n"]
        held = db.one("SELECT COUNT(*) AS n FROM reservations WHERE book_id = ? AND status = 'ready'", (b["id"],))["n"]
        assert b["copies_available"] == b["copies_total"] - on_loan - held, b["id"]


# --- catalogue --------------------------------------------------------------------------------
def test_catalog_pagination_counts_only_permitted_items(demo):
    _, c, login, _ = demo
    alice, bob = login("m-alice"), login("m-bob")
    a = c.get("/catalog?page_size=5", headers=alice).json()
    b = c.get("/catalog?page_size=5", headers=bob).json()
    assert len(a["items"]) == 5 and a["pages"] == -(-a["total"] // 5)
    all_bob = c.get(f"/catalog?page_size=60", headers=bob).json()["items"]
    assert all(i["collection_id"] not in {"finance-reports", "hr-records"} for i in all_bob)
    assert "Finance" in c.get("/catalog/facets", headers=alice).json()["categories"]
    assert "Finance" not in c.get("/catalog/facets", headers=bob).json()["categories"]
    assert b["total"] != a["total"]


def test_search_text_never_reveals_restricted_titles(demo):
    _, c, login, _ = demo
    r = c.get("/catalog?q=Forecast", headers=login("m-dave")).json()
    assert r["total"] == 0 and r["items"] == []


def test_catalog_filters_and_sorting(demo):
    _, c, login, _ = demo
    h = login("m-dave")
    digital = c.get("/catalog?format=digital&page_size=60", headers=h).json()["items"]
    assert digital and all(i["has_digital"] for i in digital)
    recent = c.get("/catalog?sort=recent&page_size=60", headers=h).json()["items"]
    assert [i["added_at"] for i in recent] == sorted((i["added_at"] for i in recent), reverse=True)
    years = [i["year"] for i in c.get("/catalog?sort=year&page_size=60", headers=h).json()["items"]]
    assert years == sorted(years, reverse=True)
    cat = c.get("/catalog?category=Literature&page_size=60", headers=h).json()["items"]
    assert cat and all(i["category"] == "Literature" for i in cat)
    by_author = c.get("/catalog?author=Strang", headers=h).json()["items"]
    assert [i["id"] for i in by_author] == ["b-018"]
    assert c.get("/catalog?q=evolution", headers=h).json()["total"] >= 1  # keyword in description


def test_recommendations_explain_and_respect_access(demo):
    _, c, login, _ = demo
    for member in ("m-dave", "m-bob", "m-erin"):
        recs = c.get("/me/recommendations?limit=20", headers=login(member)).json()
        assert recs and all(r["reason"] for r in recs)
        assert all(r["collection_id"] not in {"finance-reports", "hr-records"} for r in recs)


# --- member views -----------------------------------------------------------------------------
def test_loan_statuses_and_fines(demo):
    _, c, login, _ = demo
    alice = c.get("/me/loans", headers=login("m-alice")).json()
    assert {l["book_id"]: l["status"] for l in alice}["b-013"] == "due_soon"
    carol = login("m-carol")
    loans = c.get("/me/loans", headers=carol).json()
    assert loans[0]["status"] == "overdue" and loans[0]["fine"] == 3.0
    fines = c.get("/me/fines", headers=carol).json()
    assert fines["accruing"] == 3.0 and fines["payment_available"] is False


def test_history_and_activity(demo):
    _, c, login, _ = demo
    h = login("m-dave")
    history = c.get("/me/history", headers=h).json()
    assert any(l["status"] == "returned" for l in history)
    assert c.get("/me/activity", headers=h).json()
    access = {a["collection_id"] for a in c.get("/me/access", headers=h).json()}
    assert access == {"general", "research"}


def test_cancel_waiting_reservation(demo):
    _, c, login, _ = demo
    dave = login("m-dave")
    res = c.get("/me/reservations", headers=dave).json()
    assert res[0]["book_id"] == "b-023" and res[0]["queue_position"] == 1
    assert c.delete(f"/me/reservations/{res[0]['id']}", headers=login("m-erin")).status_code == 404  # not hers
    assert c.delete(f"/me/reservations/{res[0]['id']}", headers=dave).json()["status"] == "cancelled"
    assert c.get("/me/reservations", headers=dave).json() == []
    assert c.get("/me/reservations?all=true", headers=dave).json()[0]["status"] == "cancelled"
    assert c.delete(f"/me/reservations/{res[0]['id']}", headers=dave).status_code == 409


def test_cancel_ready_reservation_releases_copy_consistently(demo):
    _, c, login, _ = demo
    bob, dave, erin = login("m-bob"), login("m-dave"), login("m-erin")
    r = c.post("/books/b-023/reserve", json={"attestation": att(c, erin, "b-023")}, headers=erin)
    assert r.json()["queue_position"] == 2
    loan = next(l for l in c.get("/me/loans", headers=bob).json() if l["book_id"] == "b-023")
    c.post(f"/loans/{loan['loan_id']}/return", headers=bob)
    dave_res = c.get("/me/reservations", headers=dave).json()[0]
    assert dave_res["status"] == "ready"
    out = c.delete(f"/me/reservations/{dave_res['id']}", headers=dave).json()
    assert out["held_copy_passed_to"] == "m-erin"
    assert c.get("/me/reservations", headers=erin).json()[0]["status"] == "ready"
    c.delete(f"/me/reservations/{c.get('/me/reservations', headers=erin).json()[0]['id']}", headers=erin)
    assert c.get("/books/b-023", headers=erin).json()["copies_available"] == 1  # back on the shelf


def test_renewal_counts_and_reports_blocking(demo):
    _, c, login, _ = demo
    bob = login("m-bob")
    loan = next(l for l in c.get("/me/loans", headers=bob).json() if l["book_id"] == "b-023")
    assert loan["renewable"] is False and "waiting" in loan["renew_blocked_reason"]
    dave = login("m-dave")
    loan = c.get("/me/loans", headers=dave).json()[0]
    assert c.post(f"/loans/{loan['loan_id']}/renew", json={"attestation": att(c, dave, loan["book_id"])},
                  headers=dave).status_code == 200
    assert c.get("/me/loans", headers=dave).json()[0]["renewals"] == 1


def test_business_rule_denials_are_audited(demo):
    _, c, login, _ = demo
    carol = login("m-carol")  # has an overdue loan
    r = c.post("/books/b-001/checkout", json={"attestation": att(c, carol, "b-001")}, headers=carol)
    assert r.json()["error"] == "overdue_items"
    log = c.get("/admin/audit/search?member=m-carol&decision=deny", headers=login("m-libby")).json()
    assert any(e["action"] == "borrow" and e["reason"] == "overdue_items" for e in log["items"])


def test_read_requires_layer2_and_digital_edition(demo):
    _, c, login, _ = demo
    dave = login("m-dave")
    assert c.post("/books/b-025/read", json={}, headers=dave).json()["error"] == "missing_attestation"
    r = c.post("/books/b-025/read", json={"attestation": att(c, dave, "b-025")}, headers=dave)
    assert r.status_code == 200 and "Letter 1" in r.json()["content"]
    assert c.post("/books/b-002/read", json={"attestation": att(c, dave, "b-002")}, headers=dave).status_code == 404


# --- librarian --------------------------------------------------------------------------------
ADMIN_GETS = ["/admin/books", "/admin/members", "/admin/loans", "/admin/reservations", "/admin/fines",
              "/admin/reports", "/admin/access", "/admin/audit/search", "/admin/stats"]


@pytest.mark.parametrize("path", ADMIN_GETS)
def test_admin_views_require_librarian(demo, path):
    _, c, login, _ = demo
    assert c.get(path, headers=login("m-dave")).status_code == 403
    assert c.get(path).status_code == 401
    assert c.get(path, headers=login("m-libby")).status_code == 200


def test_member_cannot_edit_inventory(demo):
    _, c, login, _ = demo
    assert c.patch("/admin/books/b-001", json={"copies_total": 99}, headers=login("m-dave")).status_code == 403


def test_inventory_update_keeps_stock_consistent(demo):
    _, c, login, _ = demo
    libby = login("m-libby")
    # Nineteen Eighty-Four: 1 copy, on loan to Bob.
    r = c.patch("/admin/books/b-023", json={"copies_total": 0}, headers=libby)
    assert r.status_code == 409 and r.json()["error"] == "invalid_copies"
    r = c.patch("/admin/books/b-023", json={"copies_total": 3, "description": "Updated"}, headers=libby)
    assert r.json()["copies_available"] == 2 and r.json()["description"] == "Updated"
    assert c.patch("/admin/books/b-023", json={"title": ""}, headers=libby).status_code == 422
    r = c.patch("/admin/books/b-023", json={"description": None, "cover_url": None}, headers=libby)
    assert r.status_code == 200 and r.json()["description"] == ""


def test_moving_title_to_restricted_collection_hides_it_at_once(demo):
    _, c, login, _ = demo
    dave, libby = login("m-dave"), login("m-libby")
    a = att(c, dave, "b-001")
    c.patch("/admin/books/b-001", json={"collection_id": "hr-records"}, headers=libby)
    assert c.get("/books/b-001", headers=dave).status_code == 404
    r = c.post("/books/b-001/checkout", json={"attestation": a}, headers=dave)
    assert r.status_code == 403  # old attestation no longer matches the item


def test_admin_lists_and_reports(demo):
    _, c, login, _ = demo
    libby = login("m-libby")
    overdue = c.get("/admin/loans?status=overdue", headers=libby).json()
    assert overdue["total"] >= 1 and all(l["status"] == "overdue" for l in overdue["items"])
    members = {m["id"]: m for m in c.get("/admin/members", headers=libby).json()}
    assert members["m-libby"]["role"] == "Librarian" and members["m-carol"]["overdue_loans"] == 1
    assert "email" in members["m-alice"] and "token" not in str(members)
    rep = c.get("/admin/reports", headers=libby).json()
    assert len(rep["monthly"]) == 6
    total_loans = c.get("/admin/loans?page_size=100", headers=libby).json()["total"]
    assert sum(s["count"] for s in rep["loan_status"]) == total_loans
    fines = c.get("/admin/fines", headers=libby).json()
    assert fines["accruing_total"] >= 3.0 and fines["payment_available"] is False
    stats = c.get("/admin/stats", headers=libby).json()
    assert stats["books"] == 40 and stats["available_copies"] <= stats["copies"]


def test_librarian_can_cancel_any_reservation(demo):
    _, c, login, _ = demo
    libby = login("m-libby")
    res = c.get("/admin/reservations", headers=libby).json()
    assert res and res[0]["member_name"]
    assert c.delete(f"/admin/reservations/{res[0]['id']}", headers=libby).json()["status"] == "cancelled"


def test_audit_search_filters_and_paginates(demo):
    _, c, login, _ = demo
    libby = login("m-libby")
    c.get("/books", headers=login("m-dave"))  # produces a Layer 1 deny entry
    page = c.get("/admin/audit/search?decision=deny&page_size=2", headers=libby).json()
    assert page["total"] >= 1 and len(page["items"]) <= 2
    assert all(e["decision"] == "deny" for e in page["items"])
    assert "layer1_filter" in page["actions"]


def test_add_ebook_only_title(demo):
    _, c, login, _ = demo
    libby = login("m-libby")
    body = {"id": "b-900", "isbn": "x", "title": "E-only", "author": "A", "category": "Reference",
            "collection_id": "general", "copies": 0}
    assert c.post("/admin/books", json=body, headers=libby).status_code == 422
    body["digital_content"] = "## One\nText"
    assert c.post("/admin/books", json=body, headers=libby).status_code == 201
    dave = login("m-dave")
    r = c.post("/books/b-900/checkout", json={"attestation": att(c, dave, "b-900")}, headers=dave)
    assert r.json()["error"] == "digital_only"


# --- public landing + routing ------------------------------------------------------------------
def test_public_endpoints_expose_only_open_collections(demo):
    _, c, *_ = demo
    books = c.get("/public/books?limit=24").json()
    assert books and all("attestation" not in b and "content" not in b for b in books)
    ids = {b["id"] for b in c.get("/public/books?sort=recent&limit=24").json()} | {b["id"] for b in books}
    assert not ids & {"b-006", "b-007", "b-008", "b-009", "b-010", "b-011", "b-014"}
    ov = c.get("/public/overview").json()
    assert ov["titles"] > 0 and ov["loans_served"] > 0


def test_api_prefix_and_spa_navigation(demo):
    _, c, login, _ = demo
    h = login("m-dave")
    assert c.get("/api/me", headers=h).json()["id"] == "m-dave"
    assert c.get("/api/books").status_code == 401  # same protection under /api
    nav = c.get("/books", headers={"Accept": "text/html"})
    assert nav.status_code == 200 and "text/html" in nav.headers["content-type"]
    assert c.get("/books", headers={**h, "Accept": "application/json"}).headers["content-type"].startswith("application/json")
    assert c.get("/docs", headers={"Accept": "text/html"}).status_code == 200


def test_demo_members_listing(demo):
    _, c, *_ = demo
    people = {m["id"]: m for m in c.get("/auth/demo-members").json()}
    assert people["m-libby"]["role"] == "Librarian" and "m-alice" in people
