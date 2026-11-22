from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from typing import Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS members (
    id TEXT PRIMARY KEY,              -- immutable principal id (never the email)
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memberships (
    member_id TEXT NOT NULL REFERENCES members(id),
    group_id TEXT NOT NULL REFERENCES groups(id),
    PRIMARY KEY (member_id, group_id)
);
CREATE TABLE IF NOT EXISTS collections (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);
-- Access grants: a principal (member or group) may use a collection.
CREATE TABLE IF NOT EXISTS grants (
    collection_id TEXT NOT NULL REFERENCES collections(id),
    principal_type TEXT NOT NULL CHECK (principal_type IN ('member', 'group')),
    principal_id TEXT NOT NULL,
    PRIMARY KEY (collection_id, principal_type, principal_id)
);
-- Each change to grants or memberships produces a new policy revision.
CREATE TABLE IF NOT EXISTS policy_revisions (
    revision INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS books (
    id TEXT PRIMARY KEY,
    isbn TEXT NOT NULL,
    title TEXT NOT NULL,
    author TEXT NOT NULL,
    category TEXT NOT NULL,
    year INTEGER,
    collection_id TEXT NOT NULL REFERENCES collections(id),
    copies_total INTEGER NOT NULL DEFAULT 1,
    copies_available INTEGER NOT NULL DEFAULT 1,
    digital_content TEXT              -- e-book / digital excerpt, released only after Layer 2
);
CREATE TABLE IF NOT EXISTS loans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    book_id TEXT NOT NULL REFERENCES books(id),
    member_id TEXT NOT NULL REFERENCES members(id),
    borrowed_at REAL NOT NULL,
    due_at REAL NOT NULL,
    returned_at REAL,
    fine REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    book_id TEXT NOT NULL REFERENCES books(id),
    member_id TEXT NOT NULL REFERENCES members(id),
    created_at REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'waiting'   -- waiting | ready | fulfilled | cancelled
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at REAL NOT NULL,
    member_id TEXT,
    action TEXT NOT NULL,
    resource TEXT,
    decision TEXT NOT NULL,            -- allow | deny | info
    reason TEXT NOT NULL,
    policy_revision INTEGER
);
"""


class Database:
    """Thin thread-safe wrapper around sqlite3."""

    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, params).fetchall())

    def one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()
