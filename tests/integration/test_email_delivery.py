import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.config import settings
from apps.api.accessproof_api.db import Base, EmailOutbox, SessionLocal, engine
from apps.worker.accessproof_worker.main import process_email
from packages.crypto.secrets import SecretBox


@pytest.mark.asyncio
async def test_transactional_email_tokens_are_encrypted_and_worker_delivers_console_message():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        signup = client.post(
            "/api/v1/auth/signup",
            json={
                "email": "mail@example.com",
                "password": "correct horse battery staple",
                "organization_name": "Mail Org",
            },
        )
        assert signup.status_code == 201
        body = signup.json()
        token = body["development_verification_token"]

    with SessionLocal() as db:
        row = db.scalar(select(EmailOutbox).where(EmailOutbox.template == "verify_email"))
        assert row is not None
        assert row.status == "pending"
        assert token not in row.encrypted_payload
        payload = json.loads(
            SecretBox.from_text(settings.secret_encryption_key).decrypt(row.encrypted_payload)
        )
        assert token in payload["text_body"]
        row_id = row.id

    await process_email(row_id)

    with SessionLocal() as db:
        row = db.get(EmailOutbox, row_id)
        assert row.status == "delivered"
        assert row.completed_at is not None


def test_password_reset_and_invitation_queue_transactional_email():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        owner = client.post(
            "/api/v1/auth/signup",
            json={
                "email": "owner-mail@example.com",
                "password": "correct horse battery staple",
                "organization_name": "Owner Mail Org",
            },
        ).json()
        client.post("/api/v1/auth/forgot-password", json={"email": "owner-mail@example.com"})
        headers = {
            "Authorization": f"Bearer {owner['session_token']}",
            "X-Organization-ID": owner["organization_id"],
        }
        response = client.post(
            "/api/v1/organization/invitations",
            headers=headers,
            json={"email": "invitee@example.com", "role": "ENGINEER"},
        )
        assert response.status_code == 201

    with SessionLocal() as db:
        templates = list(db.scalars(select(EmailOutbox.template)))
        assert "verify_email" in templates
        assert "password_reset" in templates
        assert "organization_invitation" in templates
