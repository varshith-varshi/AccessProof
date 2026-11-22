import os
import sys
from pathlib import Path

import pytest

os.environ["SLMS_NO_AUTOAPP"] = "1"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from app.clock import Clock  # noqa: E402
from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture()
def clock():
    return Clock(start=1_800_000_000.0)


@pytest.fixture()
def app(tmp_path, clock):
    settings = Settings(db_path=str(tmp_path / "lib.db"), secret_key="test-secret", max_policy_staleness_seconds=600)
    return create_app(settings, clock, background_sync=False)


@pytest.fixture()
def client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def login(client):
    def _login(member_id: str) -> dict:
        r = client.post("/auth/demo-login", json={"member_id": member_id})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['access_token']}"}
    return _login


def find(client, headers, book_id):
    """Search the catalogue (Layer 1) and return the attested item, or None if hidden."""
    for b in client.get("/books", headers=headers).json():
        if b["id"] == book_id:
            return b
    return None
