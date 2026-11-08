"""SQLite FTS5 retrieval index, atomically replaced after complete source sync."""
from __future__ import annotations

import json
from contextlib import closing
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from app.graph import SourceDoc


@dataclass(frozen=True)
class Match:
    doc_id: str
    chunk_id: str
    text: str
    version: str
    name: str
    url: str
    attestation: str
    score: float


def chunks_of(body: str, chunk_words: int = 180, overlap: int = 32) -> list[str]:
    if not (10 <= chunk_words <= 1024 and 0 <= overlap < chunk_words):
        raise ValueError("CHUNK_SETTINGS_INVALID")
    words = body.split()
    result = []
    for start in range(0, len(words), chunk_words - overlap):
        block = " ".join(words[start:start + chunk_words])
        if block:
            result.append(block)
        if start + chunk_words >= len(words):
            break
    return result


# Natural-language questions include common filler words. Filtering them out
# prevents BM25 OR queries from ranking unrelated files by those words alone.
_QUESTION_STOPWORDS = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "by", "can", "could", "did",
    "do", "does", "explain", "find", "for", "from", "give", "how", "i",
    "in", "is", "it", "me", "of", "on", "our", "please", "show", "summarize",
    "tell", "that", "the", "their", "there", "these", "this", "to", "us",
    "was", "were", "what", "when", "where", "which", "who", "why", "with",
    "would", "you", "your",
})


class Index:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with closing(self._open()) as db, db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("CREATE VIRTUAL TABLE IF NOT EXISTS chunks USING fts5("
                       "text, doc_id UNINDEXED, chunk_id UNINDEXED, name UNINDEXED, "
                       "url UNINDEXED, version UNINDEXED, attestation UNINDEXED)")

    def _open(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=15000")
        return db

    def replace(self, documents: list[SourceDoc], signed_chunks: list[dict]) -> dict:
        """Commit all chunks together; failures never replace a working index."""
        if len(signed_chunks) > 50_000:
            raise ValueError("TOO_MANY_CHUNKS")
        doc_map = {d.item_id: d for d in documents}
        if len(doc_map) != len(documents):
            raise ValueError("DUPLICATE_SOURCE_ITEM")
        for c in signed_chunks:
            doc = doc_map.get(c["doc_id"])
            if (doc is None or c["version"] != doc.version
                    or not c["attestation"] or not c["text"]):
                raise ValueError("CHUNK_BINDING_INVALID")
        stamp = str(int(time.time()))
        with closing(self._open()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM chunks")
            db.executemany(
                "INSERT INTO chunks (text, doc_id, chunk_id, name, url, version, attestation) "
                "VALUES (:text, :doc_id, :chunk_id, :name, :url, :version, :attestation)",
                signed_chunks,
            )
            db.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", ("last_sync", stamp))
            db.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", ("docs", str(len(documents))))
            db.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", ("chunks", str(len(signed_chunks))))
            db.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", ("generation", str(time.time_ns())))
        return {"documents": len(documents), "chunks": len(signed_chunks), "last_sync": stamp}

    def stats(self) -> dict:
        with closing(self._open()) as db, db:
            return {row["key"]: row["value"] for row in db.execute("SELECT key, value FROM metadata")}

    def by_name(self, document_name: str, limit: int = 5) -> list[Match]:
        """Retrieve exact signed canary document, never a caller-provided excerpt.

        User-specified titles are data, not SQL or proof of authorization.
        Every returned chunk still requires Gateway L1/L2 authorization.
        """
        if not document_name or len(document_name) > 120 or "/" in document_name or "\\" in document_name:
            return []
        with closing(self._open()) as db, db:
            rows = db.execute(
                "SELECT doc_id, chunk_id, text, version, name, url, attestation, "
                "0.0 AS score FROM chunks WHERE name = ? ORDER BY rowid LIMIT ?",
                (document_name, max(1, min(limit, 20))),
            ).fetchall()
        return [Match(**dict(row)) for row in rows]

    def search(self, question: str, limit: int = 5) -> list[Match]:
        """Find relevant signed indexed chunks from the QUESTION, not a file picker.

        FTS5 identifies content candidates. Reranking favors more distinct
        meaningful query terms and matching document titles over isolated
        stopword/BM25 hits. This is RELEVANCE ONLY: each resulting attested
        chunk still requires AccessProof Gateway Layer 1 and Layer 2 checks.
        """
        terms = list(dict.fromkeys(
            token for token in re.findall(r"[a-zA-Z0-9]{2,}", question.lower())
            if token not in _QUESTION_STOPWORDS
        ))[:20]
        if not terms:
            return []
        query = " OR ".join('"' + token + '"' for token in terms)
        top_k = max(1, min(limit, 20))
        # Retrieve extra FTS candidates before reranking so a generic BM25 hit
        # cannot displace a more relevant document solely by row ordering.
        candidates = min(300, max(60, top_k * 12))
        with closing(self._open()) as db, db:
            rows = db.execute(
                "SELECT doc_id, chunk_id, text, version, name, url, attestation, "
                "bm25(chunks) AS score FROM chunks WHERE chunks MATCH ? "
                "ORDER BY score ASC LIMIT ?", (query, candidates),
            ).fetchall()
        meaningful = set(terms)
        ranked = []
        for row in rows:
            match = Match(**dict(row))
            content_terms = set(re.findall(r"[a-z0-9]{2,}", match.text.lower()))
            title_terms = set(re.findall(r"[a-z0-9]{2,}", match.name.lower()))
            overlap = meaningful & (content_terms | title_terms)
            title_overlap = meaningful & title_terms
            if not overlap:
                continue
            ranked.append((
                -len(overlap), -len(title_overlap), match.score,
                match.doc_id, match.chunk_id, match,
            ))
        ranked.sort(key=lambda item: item[:5])
        return [entry[5] for entry in ranked[:top_k]]
