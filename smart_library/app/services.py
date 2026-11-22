"""Library business logic: catalogue, loans, reservations, fines and recommendations.

Every read of the catalogue passes through Guard Layer 1, and every release (checkout,
renewal, reservation, digital reading) passes through Guard Layer 2.
"""
from __future__ import annotations

import math
from collections import Counter

from .clock import Clock
from .config import Settings
from .db import Database
from .guard import Guard, GuardError
from .policy import PolicyStore

DAY = 86400.0


class LibraryError(Exception):
    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _book(row) -> dict:
    keys = row.keys()
    return {
        "id": row["id"],
        "isbn": row["isbn"],
        "title": row["title"],
        "author": row["author"],
        "category": row["category"],
        "year": row["year"],
        "collection_id": row["collection_id"],
        "copies_total": row["copies_total"],
        "copies_available": row["copies_available"],
        "has_digital": row["digital_content"] is not None,
        "description": row["description"] if "description" in keys else "",
        "cover_url": row["cover_url"] if "cover_url" in keys else None,
        "added_at": row["added_at"] if "added_at" in keys else None,
        "loan_count": row["loan_count"] if "loan_count" in keys else None,
    }


BOOK_SELECT = "SELECT b.*, (SELECT COUNT(*) FROM loans l WHERE l.book_id = b.id) AS loan_count FROM books b"
SORTS = {
    "title": lambda b: (b["title"].lower(),),
    "recent": lambda b: (-(b["added_at"] or 0), b["title"].lower()),
    "year": lambda b: (-(b["year"] or -10**6), b["title"].lower()),
    "year_asc": lambda b: ((b["year"] if b["year"] is not None else 10**6), b["title"].lower()),
    "popular": lambda b: (-(b["loan_count"] or 0), b["title"].lower()),
    "author": lambda b: (b["author"].lower(), b["title"].lower()),
}


class LibraryService:
    def __init__(self, db: Database, store: PolicyStore, guard: Guard, clock: Clock, settings: Settings) -> None:
        self.db = db
        self.store = store
        self.guard = guard
        self.clock = clock
        self.settings = settings

    # --- members -----------------------------------------------------------------------
    def member(self, member_id: str) -> dict:
        row = self.db.one("SELECT * FROM members WHERE id = ?", (member_id,))
        if row is None:
            raise LibraryError("unknown_member", "member not found", 404)
        groups = [r["group_id"] for r in self.db.query("SELECT group_id FROM memberships WHERE member_id = ?", (member_id,))]
        return {"id": row["id"], "name": row["name"], "email": row["email"], "active": bool(row["active"]), "groups": groups}

    def is_librarian(self, member_id: str) -> bool:
        return self.db.one(
            "SELECT 1 FROM memberships m JOIN members u ON u.id = m.member_id"
            " WHERE m.member_id = ? AND m.group_id = 'librarians' AND u.active = 1",
            (member_id,),
        ) is not None

    # --- catalogue (Layer 1) -----------------------------------------------------------
    def _raw_book(self, book_id: str) -> dict:
        row = self.db.one(BOOK_SELECT + " WHERE b.id = ?", (book_id,))
        if row is None:
            raise LibraryError("unknown_book", "book not found", 404)
        return _book(row)

    def search(self, member_id: str, q: str = "", category: str | None = None, available_only: bool = False,
               author: str | None = None, fmt: str | None = None, sort: str = "title") -> list[dict]:
        sql = BOOK_SELECT + " WHERE 1=1"
        params: list = []
        if q:
            sql += (" AND (b.title LIKE ? OR b.author LIKE ? OR b.isbn LIKE ? OR b.category LIKE ?"
                    " OR b.description LIKE ?)")
            like = f"%{q}%"
            params += [like, like, like, like, like]
        if category:
            sql += " AND b.category = ?"
            params.append(category)
        if author:
            sql += " AND b.author LIKE ?"
            params.append(f"%{author}%")
        if available_only:
            sql += " AND b.copies_available > 0"
        if fmt == "digital":
            sql += " AND b.digital_content IS NOT NULL"
        elif fmt == "physical":
            sql += " AND b.copies_total > 0"
        sql += " ORDER BY b.title"
        books = [_book(r) for r in self.db.query(sql, tuple(params))]
        books.sort(key=SORTS.get(sort, SORTS["title"]))
        return self.guard.layer1_filter(member_id, books)

    def catalog(self, member_id: str, q: str = "", category: str | None = None, available_only: bool = False,
                author: str | None = None, fmt: str | None = None, sort: str = "title",
                page: int = 1, page_size: int = 12) -> dict:
        """Paginated, faceted catalogue. Totals and facets count only items that passed Layer 1."""
        items = self.search(member_id, q, category, available_only, author, fmt, sort)
        page_size = max(1, min(page_size, 60))
        page = max(1, page)
        start = (page - 1) * page_size
        return {"items": items[start:start + page_size], "total": len(items), "page": page,
                "page_size": page_size, "pages": max(1, math.ceil(len(items) / page_size))}

    def facets(self, member_id: str) -> dict:
        allowed = self.search(member_id)
        return {
            "categories": sorted({b["category"] for b in allowed}),
            "authors": sorted({b["author"] for b in allowed}),
            "total": len(allowed),
            "digital": sum(1 for b in allowed if b["has_digital"]),
        }

    def get_book(self, member_id: str, book_id: str) -> dict:
        allowed = self.guard.layer1_filter(member_id, [self._raw_book(book_id)])
        if not allowed:
            # Same answer as a missing book: restricted titles are not disclosed.
            raise LibraryError("unknown_book", "book not found", 404)
        return allowed[0]

    def recommendations(self, member_id: str, limit: int = 5) -> list[dict]:
        """Smart recommendations: titles co-borrowed by readers with similar history,
        then the member's favourite categories, then popular titles. Always Layer-1 filtered.
        Each item carries a plain-language ``reason`` explaining why it was suggested."""
        history = {r["book_id"] for r in self.db.query("SELECT book_id FROM loans WHERE member_id = ?", (member_id,))}
        scores: Counter[str] = Counter()
        reasons: dict[str, str] = {}
        if history:
            marks = ",".join("?" * len(history))
            peers = [r["member_id"] for r in self.db.query(
                f"SELECT DISTINCT member_id FROM loans WHERE book_id IN ({marks}) AND member_id != ?",
                (*history, member_id),
            )]
            for peer in peers:
                for r in self.db.query("SELECT book_id FROM loans WHERE member_id = ?", (peer,)):
                    if r["book_id"] not in history:
                        scores[r["book_id"]] += 3
                        reasons.setdefault(r["book_id"], "Borrowed by readers with similar borrowing history")
            cats = Counter(r["category"] for r in self.db.query(
                f"SELECT category FROM books WHERE id IN ({marks})", tuple(history)))
            for r in self.db.query("SELECT id, category FROM books"):
                if r["id"] not in history and r["category"] in cats:
                    scores[r["id"]] += cats[r["category"]]
                    reasons.setdefault(r["id"], f"You often borrow {r['category']} titles")
        for r in self.db.query("SELECT book_id, COUNT(*) AS n FROM loans GROUP BY book_id"):
            if r["book_id"] not in history:
                scores[r["book_id"]] += 0.1 * r["n"]
                reasons.setdefault(r["book_id"], f"Popular with members ({r['n']} loans)")
        ranked = [b for b, _ in sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))]
        if not ranked:
            ranked = [r["id"] for r in self.db.query("SELECT id FROM books ORDER BY title")]
        books = [{**self._raw_book(b), "reason": reasons.get(b, "From the catalogue")} for b in ranked]
        return self.guard.layer1_filter(member_id, books)[:limit]

    # --- shared helpers ------------------------------------------------------------------
    def _log(self, member_id: str | None, action: str, resource: str | None, decision: str, reason: str) -> None:
        self.guard.audit(member_id, action, resource, decision, reason, self.store.current_revision())

    def _loan_status(self, due_at: float, returned_at: float | None, now: float) -> str:
        if returned_at is not None:
            return "returned"
        if now > due_at:
            return "overdue"
        if due_at - now <= self.settings.due_soon_days * DAY:
            return "due_soon"
        return "active"

    def _loan_view(self, r, now: float) -> dict:
        waiting = self.db.one("SELECT 1 FROM reservations WHERE book_id = ? AND status = 'waiting'", (r["book_id"],))
        returned = r["returned_at"]
        return {
            "loan_id": r["id"], "book_id": r["book_id"], "title": r["title"], "author": r["author"],
            "category": r["category"], "cover_url": r["cover_url"], "member_id": r["member_id"],
            "borrowed_at": r["borrowed_at"], "due_at": r["due_at"], "returned_at": returned,
            "status": self._loan_status(r["due_at"], returned, now),
            "days_left": math.floor((r["due_at"] - now) / DAY) if returned is None else None,
            "renewals": r["renewals"],
            "renewable": returned is None and waiting is None,
            "renew_blocked_reason": None if waiting is None or returned is not None
            else "another member is waiting for this title",
            "fine": r["fine"] if returned is not None else self._fine(r["due_at"], now),
        }

    LOAN_SELECT = ("SELECT l.*, b.title, b.author, b.category, b.cover_url FROM loans l"
                   " JOIN books b ON b.id = l.book_id")

    # --- loans (Layer 2) ---------------------------------------------------------------
    def active_loans(self, member_id: str) -> list[dict]:
        now = self.clock.now()
        out = []
        for r in self.db.query(self.LOAN_SELECT + " WHERE l.member_id = ? AND l.returned_at IS NULL ORDER BY l.due_at",
                               (member_id,)):
            view = self._loan_view(r, now)
            view.update({"overdue": now > r["due_at"], "fine_if_returned_now": self._fine(r["due_at"], now)})
            out.append(view)
        return out

    def loan_history(self, member_id: str) -> list[dict]:
        now = self.clock.now()
        return [self._loan_view(r, now) for r in self.db.query(
            self.LOAN_SELECT + " WHERE l.member_id = ? ORDER BY l.borrowed_at DESC", (member_id,))]

    def member_fines(self, member_id: str) -> dict:
        now = self.clock.now()
        history = [self._loan_view(r, now) for r in self.db.query(
            self.LOAN_SELECT + " WHERE l.member_id = ? AND l.returned_at IS NOT NULL AND l.fine > 0"
            " ORDER BY l.returned_at DESC", (member_id,))]
        accruing = [l for l in self.active_loans(member_id) if l["overdue"]]
        return {
            "outstanding": self.outstanding_fines(member_id),
            "accruing": round(sum(l["fine_if_returned_now"] for l in accruing), 2),
            "fine_per_day": self.settings.fine_per_day,
            "history": history,
            "overdue_loans": accruing,
            "payment_available": False,
        }

    def _fine(self, due_at: float, returned_at: float) -> float:
        late_days = math.ceil((returned_at - due_at) / DAY) if returned_at > due_at else 0
        return round(late_days * self.settings.fine_per_day, 2)

    def outstanding_fines(self, member_id: str) -> float:
        row = self.db.one("SELECT COALESCE(SUM(fine), 0) AS f FROM loans WHERE member_id = ? AND returned_at IS NOT NULL", (member_id,))
        return round(float(row["f"]), 2)

    def checkout(self, member_id: str, book_id: str, attestation: str | None) -> dict:
        book = self._raw_book(book_id)
        self.guard.layer2_release(member_id, book, attestation, "checkout")
        try:
            result = self._checkout(member_id, book_id, book)
        except LibraryError as err:
            self._log(member_id, "borrow", book_id, "deny", err.code)
            raise
        self._log(member_id, "borrow", book_id, "info", f"loan {result['loan_id']} created, due in "
                  f"{self.settings.loan_days} days")
        return result

    def _checkout(self, member_id: str, book_id: str, book: dict) -> dict:
        if len(self.active_loans(member_id)) >= self.settings.max_active_loans:
            raise LibraryError("loan_limit", f"limit of {self.settings.max_active_loans} active loans reached", 409)
        if any(l["overdue"] for l in self.active_loans(member_id)):
            raise LibraryError("overdue_items", "return overdue items before borrowing", 409)
        if self.db.one("SELECT 1 FROM loans WHERE member_id = ? AND book_id = ? AND returned_at IS NULL", (member_id, book_id)):
            raise LibraryError("already_borrowed", "you already have this title", 409)
        if book["copies_total"] == 0:
            raise LibraryError("digital_only", "this title is available as an e-book only", 409)
        mine = self.db.one(
            "SELECT id FROM reservations WHERE book_id = ? AND member_id = ? AND status = 'ready'", (book_id, member_id))
        now = self.clock.now()
        with self.db.tx() as c:
            if mine is not None:
                # The copy on the hold shelf is this member's.
                c.execute("UPDATE reservations SET status = 'fulfilled', updated_at = ? WHERE id = ?", (now, mine["id"]))
            else:
                cur = c.execute(
                    "UPDATE books SET copies_available = copies_available - 1 WHERE id = ? AND copies_available > 0",
                    (book_id,))
                if cur.rowcount == 0:
                    held = c.execute("SELECT 1 FROM reservations WHERE book_id = ? AND status = 'ready'", (book_id,)).fetchone()
                    if held:
                        raise LibraryError("held_for_other", "the returned copy is held for another member", 409)
                    raise LibraryError("unavailable", "no copies available; place a reservation", 409)
            due = now + self.settings.loan_days * DAY
            cur = c.execute("INSERT INTO loans (book_id, member_id, borrowed_at, due_at) VALUES (?, ?, ?, ?)",
                            (book_id, member_id, now, due))
        return {"loan_id": cur.lastrowid, "book_id": book_id, "title": book["title"], "due_at": due}

    def renew(self, member_id: str, loan_id: int, attestation: str | None) -> dict:
        loan = self.db.one("SELECT * FROM loans WHERE id = ? AND member_id = ? AND returned_at IS NULL", (loan_id, member_id))
        if loan is None:
            raise LibraryError("unknown_loan", "loan not found", 404)
        book = self._raw_book(loan["book_id"])
        self.guard.layer2_release(member_id, book, attestation, "renew")
        if self.db.one("SELECT 1 FROM reservations WHERE book_id = ? AND status = 'waiting'", (loan["book_id"],)):
            self._log(member_id, "renew", loan["book_id"], "deny", "reserved")
            raise LibraryError("reserved", "another member is waiting for this title", 409)
        new_due = max(loan["due_at"], self.clock.now()) + self.settings.loan_days * DAY
        with self.db.tx() as c:
            c.execute("UPDATE loans SET due_at = ?, renewals = renewals + 1 WHERE id = ?", (new_due, loan_id))
        self._log(member_id, "renew", loan["book_id"], "info", f"loan {loan_id} renewed")
        return {"loan_id": loan_id, "due_at": new_due}

    def return_book(self, member_id: str, loan_id: int) -> dict:
        loan = self.db.one("SELECT * FROM loans WHERE id = ? AND member_id = ? AND returned_at IS NULL", (loan_id, member_id))
        if loan is None:
            raise LibraryError("unknown_loan", "loan not found", 404)
        now = self.clock.now()
        fine = self._fine(loan["due_at"], now)
        # One transaction: loan closed, fine recorded, copy either held or returned to stock.
        with self.db.tx() as c:
            c.execute("UPDATE loans SET returned_at = ?, fine = ? WHERE id = ?", (now, fine, loan_id))
            nxt = c.execute(
                "SELECT id, member_id FROM reservations WHERE book_id = ? AND status = 'waiting' ORDER BY created_at LIMIT 1",
                (loan["book_id"],)).fetchone()
            if nxt is not None:
                # Copy goes on the hold shelf for the next member in the queue.
                c.execute("UPDATE reservations SET status = 'ready', updated_at = ? WHERE id = ?", (now, nxt["id"]))
            else:
                c.execute("UPDATE books SET copies_available = copies_available + 1 WHERE id = ?", (loan["book_id"],))
        self._log(member_id, "return", loan["book_id"], "info",
                  f"loan {loan_id} returned; fine {fine:.2f}" + ("; copy held for next reservation" if nxt else ""))
        return {"loan_id": loan_id, "fine": fine, "held_for_next_reservation": nxt is not None}

    # --- reservations ------------------------------------------------------------------
    def reserve(self, member_id: str, book_id: str, attestation: str | None) -> dict:
        book = self._raw_book(book_id)
        self.guard.layer2_release(member_id, book, attestation, "reserve")
        try:
            if book["copies_available"] > 0:
                raise LibraryError("available", "a copy is available; borrow it instead", 409)
            if book["copies_total"] == 0:
                raise LibraryError("digital_only", "this title is available as an e-book only", 409)
            if self.db.one("SELECT 1 FROM reservations WHERE book_id = ? AND member_id = ? AND status IN ('waiting','ready')",
                           (book_id, member_id)):
                raise LibraryError("already_reserved", "you already reserved this title", 409)
            if self.db.one("SELECT 1 FROM loans WHERE book_id = ? AND member_id = ? AND returned_at IS NULL",
                           (book_id, member_id)):
                raise LibraryError("already_borrowed", "you already have this title on loan", 409)
        except LibraryError as err:
            self._log(member_id, "reserve", book_id, "deny", err.code)
            raise
        now = self.clock.now()
        with self.db.tx() as c:
            cur = c.execute("INSERT INTO reservations (book_id, member_id, created_at, updated_at) VALUES (?, ?, ?, ?)",
                            (book_id, member_id, now, now))
        pos = self.db.one("SELECT COUNT(*) AS n FROM reservations WHERE book_id = ? AND status = 'waiting' AND id <= ?",
                          (book_id, cur.lastrowid))["n"]
        self._log(member_id, "reserve", book_id, "info", f"reservation {cur.lastrowid} placed; queue position {pos}")
        return {"reservation_id": cur.lastrowid, "book_id": book_id, "queue_position": pos}

    def _reservation_view(self, r) -> dict:
        pos = None
        if r["status"] == "waiting":
            pos = self.db.one(
                "SELECT COUNT(*) AS n FROM reservations WHERE book_id = ? AND status = 'waiting'"
                " AND (created_at < ? OR (created_at = ? AND id <= ?))",
                (r["book_id"], r["created_at"], r["created_at"], r["id"]))["n"]
        keys = r.keys()
        return {"id": r["id"], "book_id": r["book_id"], "title": r["title"], "author": r["author"],
                "category": r["category"], "cover_url": r["cover_url"], "status": r["status"],
                "created_at": r["created_at"], "updated_at": r["updated_at"], "queue_position": pos,
                "member_id": r["member_id"], "member_name": r["member_name"] if "member_name" in keys else None}

    RES_SELECT = ("SELECT r.*, b.title, b.author, b.category, b.cover_url, m.name AS member_name FROM reservations r"
                  " JOIN books b ON b.id = r.book_id JOIN members m ON m.id = r.member_id")

    def reservations(self, member_id: str, include_closed: bool = False) -> list[dict]:
        status = "" if include_closed else " AND r.status IN ('waiting','ready')"
        order = " ORDER BY r.created_at DESC" if include_closed else " ORDER BY r.created_at"
        return [self._reservation_view(r) for r in self.db.query(
            self.RES_SELECT + " WHERE r.member_id = ?" + status + order, (member_id,))]

    def cancel_reservation(self, actor_id: str, reservation_id: int, as_librarian: bool = False) -> dict:
        r = self.db.one("SELECT * FROM reservations WHERE id = ?", (reservation_id,))
        if r is None or (r["member_id"] != actor_id and not as_librarian):
            raise LibraryError("unknown_reservation", "reservation not found", 404)
        if r["status"] not in ("waiting", "ready"):
            raise LibraryError("reservation_closed", f"reservation is already {r['status']}", 409)
        now = self.clock.now()
        passed_to = None
        with self.db.tx() as c:
            c.execute("UPDATE reservations SET status = 'cancelled', updated_at = ? WHERE id = ?", (now, reservation_id))
            if r["status"] == "ready":
                # The held copy goes to the next member in the queue, or back to the shelf.
                nxt = c.execute("SELECT id, member_id FROM reservations WHERE book_id = ? AND status = 'waiting'"
                                " ORDER BY created_at, id LIMIT 1", (r["book_id"],)).fetchone()
                if nxt is not None:
                    c.execute("UPDATE reservations SET status = 'ready', updated_at = ? WHERE id = ?", (now, nxt["id"]))
                    passed_to = nxt["member_id"]
                else:
                    c.execute("UPDATE books SET copies_available = copies_available + 1 WHERE id = ?", (r["book_id"],))
        by = "librarian" if as_librarian and r["member_id"] != actor_id else "member"
        self._log(actor_id, "cancel_reservation", r["book_id"], "info",
                  f"reservation {reservation_id} cancelled by {by}" + (f"; copy held for {passed_to}" if passed_to else ""))
        return {"reservation_id": reservation_id, "status": "cancelled", "held_copy_passed_to": passed_to}

    # --- digital reading (Layer 2) -----------------------------------------------------
    def read_digital(self, member_id: str, book_id: str, attestation: str | None) -> dict:
        row = self.db.one(BOOK_SELECT + " WHERE b.id = ?", (book_id,))
        if row is None:
            raise LibraryError("unknown_book", "book not found", 404)
        self.guard.layer2_release(member_id, _book(row), attestation, "read_digital")
        if row["digital_content"] is None:
            raise LibraryError("no_digital", "this title has no digital edition", 404)
        return {"book_id": book_id, "title": row["title"], "author": row["author"], "content": row["digital_content"]}

    # --- member activity and access ----------------------------------------------------
    def activity(self, member_id: str, limit: int = 12) -> list[dict]:
        events: list[dict] = []
        for r in self.db.query(self.LOAN_SELECT + " WHERE l.member_id = ? ORDER BY l.borrowed_at DESC LIMIT ?",
                               (member_id, limit)):
            events.append({"at": r["borrowed_at"], "type": "borrowed", "book_id": r["book_id"], "title": r["title"]})
            if r["returned_at"]:
                events.append({"at": r["returned_at"], "type": "returned", "book_id": r["book_id"], "title": r["title"],
                               "detail": f"fine {r['fine']:.2f}" if r["fine"] else None})
        for r in self.db.query(self.RES_SELECT + " WHERE r.member_id = ? ORDER BY r.created_at DESC LIMIT ?",
                               (member_id, limit)):
            events.append({"at": r["created_at"], "type": "reserved", "book_id": r["book_id"], "title": r["title"]})
            if r["status"] in ("cancelled", "ready", "fulfilled") and r["updated_at"]:
                events.append({"at": r["updated_at"], "type": f"reservation_{r['status']}", "book_id": r["book_id"],
                               "title": r["title"]})
        for r in self.db.query("SELECT * FROM audit_log WHERE member_id = ? AND decision = 'deny'"
                               " AND action LIKE 'layer2_%' ORDER BY id DESC LIMIT 5", (member_id,)):
            events.append({"at": r["at"], "type": "denied", "book_id": r["resource"], "title": None,
                           "detail": r["reason"]})
        events.sort(key=lambda e: -e["at"])
        return events[:limit]

    def access_summary(self, member_id: str) -> list[dict]:
        snap = self.store.snapshot()
        out = []
        for r in self.db.query("SELECT * FROM collections ORDER BY name"):
            ok, reason = snap.can_access(member_id, r["id"])
            if ok:  # Only collections the member may use are disclosed.
                out.append({"collection_id": r["id"], "name": r["name"], "description": r["description"],
                            "reason": reason})
        return out

    # --- public landing data (open collections only; no attestations, no content) ------
    def _public_collections(self) -> set[str]:
        snap = self.store.snapshot()
        return {c for c, grants in snap.grants.items() if ("group", "everyone") in grants}

    def public_overview(self) -> dict:
        cols = self._public_collections()
        books = [b for b in (_book(r) for r in self.db.query(BOOK_SELECT)) if b["collection_id"] in cols]
        one = lambda sql: self.db.one(sql)["n"]  # noqa: E731
        return {
            "titles": len(books),
            "copies": sum(b["copies_total"] for b in books),
            "ebooks": sum(1 for b in books if b["has_digital"]),
            "categories": len({b["category"] for b in books}),
            "members": one("SELECT COUNT(*) AS n FROM members WHERE active = 1"),
            "loans_served": one("SELECT COUNT(*) AS n FROM loans"),
        }

    def public_books(self, sort: str = "popular", limit: int = 8) -> list[dict]:
        cols = self._public_collections()
        books = [b for b in (_book(r) for r in self.db.query(BOOK_SELECT)) if b["collection_id"] in cols]
        books.sort(key=SORTS.get(sort, SORTS["popular"]))
        keep = ("id", "title", "author", "category", "year", "cover_url", "has_digital", "description", "added_at")
        return [{k: b[k] for k in keep} for b in books[:max(1, min(limit, 24))]]

    # --- librarian views ---------------------------------------------------------------
    def overdue_report(self) -> list[dict]:
        now = self.clock.now()
        return [{
            "loan_id": r["id"], "member_id": r["member_id"], "member_name": r["name"], "book_id": r["book_id"],
            "title": r["title"], "due_at": r["due_at"],
            "days_overdue": math.ceil((now - r["due_at"]) / DAY), "fine_so_far": self._fine(r["due_at"], now),
        } for r in self.db.query(
            "SELECT l.*, b.title, m.name FROM loans l JOIN books b ON b.id = l.book_id JOIN members m ON m.id = l.member_id"
            " WHERE l.returned_at IS NULL AND l.due_at < ? ORDER BY l.due_at", (now,))]

    def statistics(self) -> dict:
        one = lambda sql: self.db.one(sql)["n"]  # noqa: E731
        return {
            "books": one("SELECT COUNT(*) AS n FROM books"),
            "copies": one("SELECT COALESCE(SUM(copies_total),0) AS n FROM books"),
            "available_copies": one("SELECT COALESCE(SUM(copies_available),0) AS n FROM books"),
            "members": one("SELECT COUNT(*) AS n FROM members"),
            "active_members": one("SELECT COUNT(*) AS n FROM members WHERE active = 1"),
            "active_loans": one("SELECT COUNT(*) AS n FROM loans WHERE returned_at IS NULL"),
            "overdue_loans": len(self.overdue_report()),
            "waiting_reservations": one("SELECT COUNT(*) AS n FROM reservations WHERE status='waiting'"),
            "ready_reservations": one("SELECT COUNT(*) AS n FROM reservations WHERE status='ready'"),
            "ebooks": one("SELECT COUNT(*) AS n FROM books WHERE digital_content IS NOT NULL"),
            "denied_decisions": one("SELECT COUNT(*) AS n FROM audit_log WHERE decision='deny'"),
            "outstanding_fines": round(float(self.db.one(
                "SELECT COALESCE(SUM(fine),0) AS n FROM loans WHERE returned_at IS NOT NULL")["n"]), 2),
            "policy_revision": self.store.current_revision(),
        }

    def reports(self, months: int = 6) -> dict:
        now = self.clock.now()
        import datetime as _dt

        def month_key(ts: float) -> str:
            return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m")

        today = _dt.datetime.fromtimestamp(now, _dt.timezone.utc).replace(day=1)
        keys: list[str] = []
        y, m = today.year, today.month
        for _ in range(months):
            keys.append(f"{y:04d}-{m:02d}")
            m -= 1
            if m == 0:
                y, m = y - 1, 12
        keys.reverse()
        borrow = {k: 0 for k in keys}
        returns = {k: 0 for k in keys}
        for r in self.db.query("SELECT borrowed_at, returned_at FROM loans"):
            if month_key(r["borrowed_at"]) in borrow:
                borrow[month_key(r["borrowed_at"])] += 1
            if r["returned_at"] and month_key(r["returned_at"]) in returns:
                returns[month_key(r["returned_at"])] += 1
        res = {k: {"placed": 0, "fulfilled": 0, "cancelled": 0} for k in keys}
        for r in self.db.query("SELECT created_at, status FROM reservations"):
            k = month_key(r["created_at"])
            if k in res:
                res[k]["placed"] += 1
                if r["status"] in ("fulfilled", "cancelled"):
                    res[k][r["status"]] += 1
        status = Counter(self._loan_status(r["due_at"], r["returned_at"], now)
                         for r in self.db.query("SELECT due_at, returned_at FROM loans"))
        categories = [{"category": r["category"], "loans": r["n"]} for r in self.db.query(
            "SELECT b.category, COUNT(*) AS n FROM loans l JOIN books b ON b.id = l.book_id"
            " GROUP BY b.category ORDER BY n DESC")]
        top = [{"book_id": r["id"], "title": r["title"], "author": r["author"], "loans": r["n"]} for r in self.db.query(
            "SELECT b.id, b.title, b.author, COUNT(*) AS n FROM loans l JOIN books b ON b.id = l.book_id"
            " GROUP BY b.id ORDER BY n DESC, b.title LIMIT 8")]
        decisions = Counter(r["decision"] for r in self.db.query("SELECT decision FROM audit_log"))
        return {
            "monthly": [{"month": k, "borrowed": borrow[k], "returned": returns[k]} for k in keys],
            "reservations": [{"month": k, **res[k]} for k in keys],
            "loan_status": [{"status": s, "count": status.get(s, 0)}
                            for s in ("active", "due_soon", "overdue", "returned")],
            "categories": categories,
            "top_books": top,
            "decisions": {"allow": decisions.get("allow", 0), "deny": decisions.get("deny", 0),
                          "info": decisions.get("info", 0)},
        }

    def members_overview(self, q: str = "") -> list[dict]:
        like = f"%{q}%"
        out = []
        for r in self.db.query("SELECT * FROM members WHERE name LIKE ? OR id LIKE ? OR email LIKE ? ORDER BY name",
                               (like, like, like)):
            mid = r["id"]
            groups = [g["group_id"] for g in self.db.query(
                "SELECT group_id FROM memberships WHERE member_id = ? ORDER BY group_id", (mid,))]
            n = lambda sql: self.db.one(sql, (mid,))["n"]  # noqa: E731
            out.append({
                "id": mid, "name": r["name"], "email": r["email"], "active": bool(r["active"]), "groups": groups,
                "role": "Librarian" if "librarians" in groups else "Member",
                "active_loans": n("SELECT COUNT(*) AS n FROM loans WHERE member_id = ? AND returned_at IS NULL"),
                "overdue_loans": len([l for l in self.active_loans(mid) if l["overdue"]]),
                "reservations": n("SELECT COUNT(*) AS n FROM reservations WHERE member_id = ?"
                                  " AND status IN ('waiting','ready')"),
                "outstanding_fines": self.outstanding_fines(mid),
            })
        return out

    def all_loans(self, status: str = "all", q: str = "", page: int = 1, page_size: int = 20) -> dict:
        now = self.clock.now()
        like = f"%{q}%"
        rows = self.db.query(
            "SELECT l.*, b.title, b.author, b.category, b.cover_url, m.name AS member_name FROM loans l"
            " JOIN books b ON b.id = l.book_id JOIN members m ON m.id = l.member_id"
            " WHERE (b.title LIKE ? OR m.name LIKE ? OR l.member_id LIKE ?) ORDER BY l.borrowed_at DESC",
            (like, like, like))
        items = []
        for r in rows:
            v = {**self._loan_view(r, now), "member_name": r["member_name"]}
            if status == "all" or v["status"] == status or (status == "open" and v["status"] != "returned"):
                items.append(v)
        page_size = max(1, min(page_size, 100))
        start = (max(1, page) - 1) * page_size
        return {"items": items[start:start + page_size], "total": len(items), "page": max(1, page),
                "page_size": page_size, "pages": max(1, math.ceil(len(items) / page_size))}

    def all_reservations(self, status: str = "open") -> list[dict]:
        if status == "open":
            where = " WHERE r.status IN ('waiting','ready')"
        elif status == "all":
            where = ""
        else:
            where = " WHERE r.status = ?"
        params = (status,) if where.endswith("?") else ()
        return [self._reservation_view(r) for r in self.db.query(
            self.RES_SELECT + where + " ORDER BY r.created_at DESC", params)]

    def fines_overview(self) -> dict:
        members = [m for m in self.members_overview() if m["outstanding_fines"] or m["overdue_loans"]]
        records = self.all_loans("all", page_size=100)["items"]
        records = [r for r in records if r["fine"]]
        return {
            "outstanding_total": round(sum(m["outstanding_fines"] for m in self.members_overview()), 2),
            "accruing_total": round(sum(o["fine_so_far"] for o in self.overdue_report()), 2),
            "fine_per_day": self.settings.fine_per_day,
            "members": members,
            "records": records,
            "overdue": self.overdue_report(),
            "payment_available": False,
        }

    # --- inventory ---------------------------------------------------------------------
    def inventory(self, q: str = "") -> list[dict]:
        like = f"%{q}%"
        out = []
        for r in self.db.query(BOOK_SELECT + ", collections c WHERE c.id = b.collection_id AND"
                               " (b.title LIKE ? OR b.author LIKE ? OR b.isbn LIKE ? OR b.category LIKE ?)"
                               " ORDER BY b.title", (like, like, like, like)):
            on_loan, held = self._on_loan_and_held(r["id"])
            out.append({**_book(r), "on_loan": on_loan, "held": held})
        return out

    def _on_loan_and_held(self, book_id: str) -> tuple[int, int]:
        on_loan = self.db.one("SELECT COUNT(*) AS n FROM loans WHERE book_id = ? AND returned_at IS NULL", (book_id,))["n"]
        held = self.db.one("SELECT COUNT(*) AS n FROM reservations WHERE book_id = ? AND status = 'ready'", (book_id,))["n"]
        return on_loan, held

    def _validate_book(self, data: dict) -> None:
        for f in ("title", "author", "isbn", "category"):
            if f in data and (data[f] is None or not str(data[f]).strip()):
                raise LibraryError("invalid_field", f"{f} is required", 422)
        if "collection_id" in data and not self.db.one("SELECT 1 FROM collections WHERE id = ?", (data["collection_id"],)):
            raise LibraryError("unknown_collection", "collection not found", 404)

    def add_book(self, data: dict) -> dict:
        self._validate_book(data)
        if not self.db.one("SELECT 1 FROM collections WHERE id = ?", (data["collection_id"],)):
            raise LibraryError("unknown_collection", "collection not found", 404)
        if self.db.one("SELECT 1 FROM books WHERE id = ?", (data["id"],)):
            raise LibraryError("duplicate_book", "book id already exists", 409)
        if data["copies"] == 0 and not data.get("digital_content"):
            raise LibraryError("invalid_copies", "a title with no physical copies needs a digital edition", 422)
        with self.db.tx() as c:
            c.execute(
                "INSERT INTO books (id, isbn, title, author, category, year, collection_id, copies_total, copies_available,"
                " digital_content, description, cover_url, added_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (data["id"], data["isbn"], data["title"], data["author"], data["category"], data.get("year"),
                 data["collection_id"], data["copies"], data["copies"], data.get("digital_content"),
                 data.get("description") or "", data.get("cover_url"), self.clock.now()))
        return self._raw_book(data["id"])

    def update_book(self, book_id: str, data: dict) -> dict:
        self._raw_book(book_id)
        self._validate_book(data)
        allowed = ("isbn", "title", "author", "category", "year", "collection_id", "description", "cover_url",
                   "digital_content")
        fields = {k: v for k, v in data.items() if k in allowed}
        if "description" in fields and fields["description"] is None:
            fields["description"] = ""  # the column is NOT NULL; an empty form field clears it
        for required in ("isbn", "title", "author", "category", "collection_id"):
            if required in fields and fields[required] is None:
                del fields[required]  # null means "leave unchanged" for required fields
        on_loan, held = self._on_loan_and_held(book_id)
        with self.db.tx() as c:
            if "copies_total" in data and data["copies_total"] is not None:
                total = int(data["copies_total"])
                if total < on_loan + held:
                    raise LibraryError("invalid_copies", f"{on_loan} copies are on loan and {held} held for "
                                       f"reservations; total cannot be below {on_loan + held}", 409)
                fields["copies_total"] = total
                fields["copies_available"] = total - on_loan - held
            if fields:
                sets = ", ".join(f"{k} = ?" for k in fields)
                c.execute(f"UPDATE books SET {sets} WHERE id = ?", (*fields.values(), book_id))
        return self._raw_book(book_id)

    # --- policy views for librarians ---------------------------------------------------
    def access_overview(self) -> dict:
        cols = []
        for r in self.db.query("SELECT * FROM collections ORDER BY name"):
            grants = [dict(g) for g in self.db.query(
                "SELECT principal_type, principal_id FROM grants WHERE collection_id = ? ORDER BY principal_type,"
                " principal_id", (r["id"],))]
            n = self.db.one("SELECT COUNT(*) AS n FROM books WHERE collection_id = ?", (r["id"],))["n"]
            cols.append({"id": r["id"], "name": r["name"], "description": r["description"], "grants": grants,
                         "books": n})
        groups = []
        for g in self.db.query("SELECT * FROM groups ORDER BY name"):
            members = [m["member_id"] for m in self.db.query(
                "SELECT member_id FROM memberships WHERE group_id = ? ORDER BY member_id", (g["id"],))]
            groups.append({"id": g["id"], "name": g["name"], "members": members})
        revisions = [dict(r) for r in self.db.query(
            "SELECT * FROM policy_revisions ORDER BY revision DESC LIMIT 10")]
        return {"collections": cols, "groups": groups, "revisions": revisions}

    def audit(self, limit: int = 100) -> list[dict]:
        return [dict(r) for r in self.db.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]

    def audit_search(self, member: str | None = None, action: str | None = None, decision: str | None = None,
                     since: float | None = None, until: float | None = None, page: int = 1,
                     page_size: int = 25) -> dict:
        where, params = ["1=1"], []
        if member:
            where.append("a.member_id = ?")
            params.append(member)
        if action:
            where.append("a.action LIKE ?")
            params.append(f"%{action}%")
        if decision:
            where.append("a.decision = ?")
            params.append(decision)
        if since is not None:
            where.append("a.at >= ?")
            params.append(since)
        if until is not None:
            where.append("a.at <= ?")
            params.append(until)
        clause = " AND ".join(where)
        total = self.db.one(f"SELECT COUNT(*) AS n FROM audit_log a WHERE {clause}", tuple(params))["n"]
        page_size = max(1, min(page_size, 100))
        page = max(1, page)
        rows = self.db.query(
            f"SELECT a.*, m.name AS member_name FROM audit_log a LEFT JOIN members m ON m.id = a.member_id"
            f" WHERE {clause} ORDER BY a.id DESC LIMIT ? OFFSET ?", (*params, page_size, (page - 1) * page_size))
        actions = [r["action"] for r in self.db.query("SELECT DISTINCT action FROM audit_log ORDER BY action")]
        return {"items": [dict(r) for r in rows], "total": total, "page": page, "page_size": page_size,
                "pages": max(1, math.ceil(total / page_size)), "actions": actions}


__all__ = ["LibraryService", "LibraryError", "GuardError"]
