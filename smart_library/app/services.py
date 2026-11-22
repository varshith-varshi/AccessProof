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
        row = self.db.one("SELECT * FROM books WHERE id = ?", (book_id,))
        if row is None:
            raise LibraryError("unknown_book", "book not found", 404)
        return _book(row)

    def search(self, member_id: str, q: str = "", category: str | None = None, available_only: bool = False) -> list[dict]:
        sql = "SELECT * FROM books WHERE 1=1"
        params: list = []
        if q:
            sql += " AND (title LIKE ? OR author LIKE ? OR isbn LIKE ? OR category LIKE ?)"
            like = f"%{q}%"
            params += [like, like, like, like]
        if category:
            sql += " AND category = ?"
            params.append(category)
        if available_only:
            sql += " AND copies_available > 0"
        sql += " ORDER BY title"
        books = [_book(r) for r in self.db.query(sql, tuple(params))]
        return self.guard.layer1_filter(member_id, books)

    def get_book(self, member_id: str, book_id: str) -> dict:
        allowed = self.guard.layer1_filter(member_id, [self._raw_book(book_id)])
        if not allowed:
            # Same answer as a missing book: restricted titles are not disclosed.
            raise LibraryError("unknown_book", "book not found", 404)
        return allowed[0]

    def recommendations(self, member_id: str, limit: int = 5) -> list[dict]:
        """Smart recommendations: titles co-borrowed by readers with similar history,
        then the member's favourite categories, then popular titles. Always Layer-1 filtered."""
        history = {r["book_id"] for r in self.db.query("SELECT book_id FROM loans WHERE member_id = ?", (member_id,))}
        scores: Counter[str] = Counter()
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
            cats = Counter(r["category"] for r in self.db.query(
                f"SELECT category FROM books WHERE id IN ({marks})", tuple(history)))
            for r in self.db.query("SELECT id, category FROM books"):
                if r["id"] not in history and r["category"] in cats:
                    scores[r["id"]] += cats[r["category"]]
        for r in self.db.query("SELECT book_id, COUNT(*) AS n FROM loans GROUP BY book_id"):
            if r["book_id"] not in history:
                scores[r["book_id"]] += 0.1 * r["n"]
        ranked = [b for b, _ in sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))]
        if not ranked:
            ranked = [r["id"] for r in self.db.query("SELECT id FROM books ORDER BY title")]
        books = [self._raw_book(b) for b in ranked]
        return self.guard.layer1_filter(member_id, books)[:limit]

    # --- loans (Layer 2) ---------------------------------------------------------------
    def active_loans(self, member_id: str) -> list[dict]:
        now = self.clock.now()
        out = []
        for r in self.db.query(
            "SELECT l.*, b.title FROM loans l JOIN books b ON b.id = l.book_id"
            " WHERE l.member_id = ? AND l.returned_at IS NULL ORDER BY l.due_at", (member_id,)):
            out.append({
                "loan_id": r["id"], "book_id": r["book_id"], "title": r["title"],
                "borrowed_at": r["borrowed_at"], "due_at": r["due_at"],
                "overdue": now > r["due_at"], "fine_if_returned_now": self._fine(r["due_at"], now),
            })
        return out

    def _fine(self, due_at: float, returned_at: float) -> float:
        late_days = math.ceil((returned_at - due_at) / DAY) if returned_at > due_at else 0
        return round(late_days * self.settings.fine_per_day, 2)

    def outstanding_fines(self, member_id: str) -> float:
        row = self.db.one("SELECT COALESCE(SUM(fine), 0) AS f FROM loans WHERE member_id = ? AND returned_at IS NOT NULL", (member_id,))
        return round(float(row["f"]), 2)

    def checkout(self, member_id: str, book_id: str, attestation: str | None) -> dict:
        book = self._raw_book(book_id)
        self.guard.layer2_release(member_id, book, attestation, "checkout")
        if len(self.active_loans(member_id)) >= self.settings.max_active_loans:
            raise LibraryError("loan_limit", f"limit of {self.settings.max_active_loans} active loans reached", 409)
        if any(l["overdue"] for l in self.active_loans(member_id)):
            raise LibraryError("overdue_items", "return overdue items before borrowing", 409)
        if self.db.one("SELECT 1 FROM loans WHERE member_id = ? AND book_id = ? AND returned_at IS NULL", (member_id, book_id)):
            raise LibraryError("already_borrowed", "you already have this title", 409)
        mine = self.db.one(
            "SELECT id FROM reservations WHERE book_id = ? AND member_id = ? AND status = 'ready'", (book_id, member_id))
        now = self.clock.now()
        with self.db.tx() as c:
            if mine is not None:
                # The copy on the hold shelf is this member's.
                c.execute("UPDATE reservations SET status = 'fulfilled' WHERE id = ?", (mine["id"],))
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
            raise LibraryError("reserved", "another member is waiting for this title", 409)
        new_due = max(loan["due_at"], self.clock.now()) + self.settings.loan_days * DAY
        with self.db.tx() as c:
            c.execute("UPDATE loans SET due_at = ? WHERE id = ?", (new_due, loan_id))
        return {"loan_id": loan_id, "due_at": new_due}

    def return_book(self, member_id: str, loan_id: int) -> dict:
        loan = self.db.one("SELECT * FROM loans WHERE id = ? AND member_id = ? AND returned_at IS NULL", (loan_id, member_id))
        if loan is None:
            raise LibraryError("unknown_loan", "loan not found", 404)
        now = self.clock.now()
        fine = self._fine(loan["due_at"], now)
        with self.db.tx() as c:
            c.execute("UPDATE loans SET returned_at = ?, fine = ? WHERE id = ?", (now, fine, loan_id))
            nxt = c.execute(
                "SELECT id, member_id FROM reservations WHERE book_id = ? AND status = 'waiting' ORDER BY created_at LIMIT 1",
                (loan["book_id"],)).fetchone()
            if nxt is not None:
                # Copy goes on the hold shelf for the next member in the queue.
                c.execute("UPDATE reservations SET status = 'ready' WHERE id = ?", (nxt["id"],))
            else:
                c.execute("UPDATE books SET copies_available = copies_available + 1 WHERE id = ?", (loan["book_id"],))
        return {"loan_id": loan_id, "fine": fine, "held_for_next_reservation": nxt is not None}

    # --- reservations ------------------------------------------------------------------
    def reserve(self, member_id: str, book_id: str, attestation: str | None) -> dict:
        book = self._raw_book(book_id)
        self.guard.layer2_release(member_id, book, attestation, "reserve")
        if book["copies_available"] > 0:
            raise LibraryError("available", "a copy is available; borrow it instead", 409)
        if self.db.one("SELECT 1 FROM reservations WHERE book_id = ? AND member_id = ? AND status IN ('waiting','ready')",
                       (book_id, member_id)):
            raise LibraryError("already_reserved", "you already reserved this title", 409)
        with self.db.tx() as c:
            cur = c.execute("INSERT INTO reservations (book_id, member_id, created_at) VALUES (?, ?, ?)",
                            (book_id, member_id, self.clock.now()))
        pos = self.db.one("SELECT COUNT(*) AS n FROM reservations WHERE book_id = ? AND status = 'waiting' AND id <= ?",
                          (book_id, cur.lastrowid))["n"]
        return {"reservation_id": cur.lastrowid, "book_id": book_id, "queue_position": pos}

    def reservations(self, member_id: str) -> list[dict]:
        return [dict(r) for r in self.db.query(
            "SELECT r.id, r.book_id, b.title, r.status, r.created_at FROM reservations r JOIN books b ON b.id = r.book_id"
            " WHERE r.member_id = ? AND r.status IN ('waiting','ready') ORDER BY r.created_at", (member_id,))]

    # --- digital reading (Layer 2) -----------------------------------------------------
    def read_digital(self, member_id: str, book_id: str, attestation: str | None) -> dict:
        row = self.db.one("SELECT * FROM books WHERE id = ?", (book_id,))
        if row is None:
            raise LibraryError("unknown_book", "book not found", 404)
        self.guard.layer2_release(member_id, _book(row), attestation, "read_digital")
        if row["digital_content"] is None:
            raise LibraryError("no_digital", "this title has no digital edition", 404)
        return {"book_id": book_id, "title": row["title"], "content": row["digital_content"]}

    # --- librarian views ---------------------------------------------------------------
    def overdue_report(self) -> list[dict]:
        now = self.clock.now()
        return [{
            "loan_id": r["id"], "member_id": r["member_id"], "book_id": r["book_id"], "title": r["title"],
            "days_overdue": math.ceil((now - r["due_at"]) / DAY), "fine_so_far": self._fine(r["due_at"], now),
        } for r in self.db.query(
            "SELECT l.*, b.title FROM loans l JOIN books b ON b.id = l.book_id"
            " WHERE l.returned_at IS NULL AND l.due_at < ? ORDER BY l.due_at", (now,))]

    def statistics(self) -> dict:
        one = lambda sql: self.db.one(sql)["n"]  # noqa: E731
        return {
            "books": one("SELECT COUNT(*) AS n FROM books"),
            "copies": one("SELECT COALESCE(SUM(copies_total),0) AS n FROM books"),
            "members": one("SELECT COUNT(*) AS n FROM members"),
            "active_loans": one("SELECT COUNT(*) AS n FROM loans WHERE returned_at IS NULL"),
            "overdue_loans": len(self.overdue_report()),
            "waiting_reservations": one("SELECT COUNT(*) AS n FROM reservations WHERE status='waiting'"),
            "denied_decisions": one("SELECT COUNT(*) AS n FROM audit_log WHERE decision='deny'"),
            "policy_revision": self.store.current_revision(),
        }

    def add_book(self, data: dict) -> dict:
        if not self.db.one("SELECT 1 FROM collections WHERE id = ?", (data["collection_id"],)):
            raise LibraryError("unknown_collection", "collection not found", 404)
        if self.db.one("SELECT 1 FROM books WHERE id = ?", (data["id"],)):
            raise LibraryError("duplicate_book", "book id already exists", 409)
        with self.db.tx() as c:
            c.execute(
                "INSERT INTO books (id, isbn, title, author, category, year, collection_id, copies_total, copies_available, digital_content)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (data["id"], data["isbn"], data["title"], data["author"], data["category"], data.get("year"),
                 data["collection_id"], data["copies"], data["copies"], data.get("digital_content")))
        return self._raw_book(data["id"])

    def audit(self, limit: int = 100) -> list[dict]:
        return [dict(r) for r in self.db.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]


__all__ = ["LibraryService", "LibraryError", "GuardError"]
