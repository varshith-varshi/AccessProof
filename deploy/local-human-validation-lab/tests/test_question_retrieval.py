"""RAG question-first retrieval, run inside the existing dependency-locked image."""
import sqlite3
import tempfile
from pathlib import Path
from app.index import Index


def exercise():
    with tempfile.TemporaryDirectory() as temp:
        index = Index(str(Path(temp) / "synthetic.db"))
        with sqlite3.connect(index.path) as db:
            db.executemany(
                "INSERT INTO chunks (text,doc_id,chunk_id,name,url,version,attestation) "
                "VALUES (?,?,?,?,?,?,?)",
                [
                    ("The policy for inherited finance access uses control reviews", "finance-inherited", "c1",
                     "inherited_finance_alice.txt", "https://sharepoint.invalid/finance", "v1", "signed-1"),
                    ("The shared control policy applies to all employees", "shared-control", "c2",
                     "shared_control.txt", "https://sharepoint.invalid/shared", "v1", "signed-2"),
                    ("Engineering systems use planned deployment updates", "eng", "c3",
                     "engineering_bob.txt", "https://sharepoint.invalid/engineering", "v2", "signed-3"),
                ]
            )
        shared = index.search("Explain the shared control policy")
        assert shared and shared[0].doc_id == "shared-control", shared
        assert shared[0].attestation == "signed-2"
        eng = index.search("What is the engineering deployment update?")
        assert eng and eng[0].doc_id == "eng", eng
        assert index.search("What is it?") == []
        assert index.search("!") == []
        for string in ('" OR 1=1 --', "engineering) OR ("):
            assert isinstance(index.search(string), list)
        assert index.by_name("engineering_bob.txt")[0].doc_id == "eng"
        print("QUESTION_FIRST_RETRIEVAL_PASS: query-selected signed chunks and safe diagnostic override")


if __name__ == "__main__":
    exercise()
