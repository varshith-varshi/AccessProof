"""Demo data: members, groups, collections with different access rules, and books."""
from __future__ import annotations

from .db import Database

GROUPS = [
    ("everyone", "Everyone"),
    ("students", "Students"),
    ("faculty", "Faculty"),
    ("finance", "Finance department"),
    ("hr", "Human Resources"),
    ("librarians", "Librarians"),
]

MEMBERS = [
    # id (immutable), name, email, groups
    ("m-alice", "Alice", "alice@library.example", ["finance"]),
    ("m-bob", "Bob", "bob@library.example", ["faculty"]),
    ("m-carol", "Carol", "carol@library.example", ["hr"]),
    ("m-dave", "Dave", "dave@library.example", ["students"]),
    ("m-libby", "Libby", "libby@library.example", ["librarians"]),
]

COLLECTIONS = [
    ("general", "General lending", "Open to every member", [("group", "everyone")]),
    ("research", "Research & journals", "Faculty and students", [("group", "faculty"), ("group", "students")]),
    ("finance-reports", "Finance reports", "Forecasts and budgets", [("group", "finance")]),
    ("hr-records", "HR policy documents", "Confidential personnel material", [("group", "hr")]),
    ("rare-books", "Rare books", "Reading room only, by direct grant", [("member", "m-bob")]),
]

BOOKS = [
    # id, isbn, title, author, category, year, collection, copies, digital excerpt
    ("b-001", "9780262033848", "Introduction to Algorithms", "Cormen et al.", "Computer Science", 2009, "general", 3,
     "Chapter 1: The role of algorithms in computing..."),
    ("b-002", "9780132350884", "Clean Code", "Robert C. Martin", "Computer Science", 2008, "general", 2, None),
    ("b-003", "9780141439518", "Pride and Prejudice", "Jane Austen", "Fiction", 1813, "general", 2,
     "It is a truth universally acknowledged..."),
    ("b-004", "9780061120084", "To Kill a Mockingbird", "Harper Lee", "Fiction", 1960, "general", 1, None),
    ("b-005", "9780553380163", "A Brief History of Time", "Stephen Hawking", "Science", 1988, "general", 2, None),
    ("b-006", "9781492078005", "Designing Data-Intensive Applications", "Martin Kleppmann", "Computer Science", 2017,
     "research", 2, "Part I: Foundations of data systems..."),
    ("b-007", "9780000000001", "Journal of Library Automation, Vol. 42", "Various", "Journals", 2025, "research", 1, None),
    ("b-008", "FIN-2026-Q4", "FY2026 Q4 Financial Forecast", "Finance Office", "Finance", 2026, "finance-reports", 1,
     "Confidential: projected revenue and cost lines for Q4..."),
    ("b-009", "FIN-BUDGET-27", "FY2027 Library Budget", "Finance Office", "Finance", 2026, "finance-reports", 1, None),
    ("b-010", "HR-POL-001", "Staff Conduct and Grievance Policy", "HR Office", "HR", 2026, "hr-records", 1,
     "Confidential: grievance procedure and case handling..."),
    ("b-011", "RARE-1623", "Shakespeare First Folio (facsimile)", "William Shakespeare", "Rare", 1623, "rare-books", 1, None),
    ("b-012", "9780307474278", "The Da Vinci Code", "Dan Brown", "Fiction", 2003, "general", 1, None),
]


def seed(db: Database) -> None:
    if db.one("SELECT 1 FROM members LIMIT 1"):
        return
    with db.tx() as c:
        c.executemany("INSERT INTO groups (id, name) VALUES (?, ?)", GROUPS)
        for mid, name, email, groups in MEMBERS:
            c.execute("INSERT INTO members (id, name, email) VALUES (?, ?, ?)", (mid, name, email))
            for g in groups:
                c.execute("INSERT INTO memberships (member_id, group_id) VALUES (?, ?)", (mid, g))
        for cid, name, desc, grants in COLLECTIONS:
            c.execute("INSERT INTO collections (id, name, description) VALUES (?, ?, ?)", (cid, name, desc))
            for ptype, pid in grants:
                c.execute("INSERT INTO grants (collection_id, principal_type, principal_id) VALUES (?, ?, ?)",
                          (cid, ptype, pid))
        for bid, isbn, title, author, cat, year, col, copies, digital in BOOKS:
            c.execute(
                "INSERT INTO books (id, isbn, title, author, category, year, collection_id, copies_total,"
                " copies_available, digital_content) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (bid, isbn, title, author, cat, year, col, copies, copies, digital))
