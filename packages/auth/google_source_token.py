"""Customer-owned, durable Google OAuth token renewal for the private ingester.

The Google refresh token and client secret never enter the RAG application.
The ingester uses an owner-only JSON credentials file with atomic rotation.
"""
from __future__ import annotations

import json
import os
import secrets
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from packages.auth.oauth_refresh import (
    OAuthCredentials, refresh_credentials,
)

TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"


class TokenStoreError(ValueError):
    pass


class GoogleSourceTokenStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def _read(self) -> dict[str, Any]:
        try:
            fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or
                        stat.S_IMODE(info.st_mode) & 0o077 or
                        not 1 <= info.st_size <= 32768):
                    raise TokenStoreError("GOOGLE_TOKEN_SECRET_FILE_UNSAFE")
                with os.fdopen(fd, "rb") as reader:
                    fd = -1
                    result = json.loads(reader.read(32769))
            finally:
                if fd != -1:
                    os.close(fd)
            if not isinstance(result, dict):
                raise TokenStoreError("GOOGLE_TOKEN_SECRET_INVALID")
            return result
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise TokenStoreError("GOOGLE_TOKEN_SECRET_INVALID") from exc

    def _save(self, contents: dict[str, Any]) -> None:
        raw = json.dumps(contents, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(raw) > 32768 or not self.path.parent.is_dir() or self.path.is_symlink():
            raise TokenStoreError("GOOGLE_TOKEN_SECRET_WRITE_UNSAFE")
        # Renewals survive prior crashes without a stranded fixed temp name.
        temp = self.path.with_name(f".{self.path.name}.{secrets.token_hex(12)}.renewing")
        fd = None
        try:
            fd = os.open(
                temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            with os.fdopen(fd, "wb") as writer:
                fd = None
                writer.write(raw)
                writer.flush()
                os.fsync(writer.fileno())
            os.replace(temp, self.path)
        finally:
            if fd is not None:
                os.close(fd)
            temp.unlink(missing_ok=True)

    @staticmethod
    def _required(contents: dict[str, Any], key: str) -> str:
        value = contents.get(key)
        if not isinstance(value, str) or not value:
            raise TokenStoreError("GOOGLE_TOKEN_SECRET_INCOMPLETE")
        return value

    def access_token(self, *, client: httpx.Client | None = None) -> str:
        contents = self._read()
        access = self._required(contents, "access_token")
        refresh = self._required(contents, "refresh_token")
        client_id = self._required(contents, "client_id")
        client_secret = self._required(contents, "client_secret")
        expiry_raw = self._required(contents, "expires_at")
        try:
            expiry = datetime.fromisoformat(expiry_raw)
        except ValueError as exc:
            raise TokenStoreError("GOOGLE_TOKEN_SECRET_EXPIRY_INVALID") from exc
        if expiry.tzinfo is None:
            raise TokenStoreError("GOOGLE_TOKEN_SECRET_EXPIRY_INVALID")
        creds = OAuthCredentials(
            access_token=access, refresh_token=refresh,
            expires_at=expiry, scopes=tuple(str(contents.get("scope") or "").split()),
        )
        if not creds.needs_refresh(skew_seconds=300):
            return creds.access_token

        def save(fresh: OAuthCredentials) -> None:
            if fresh.expires_at is None:
                raise TokenStoreError("GOOGLE_TOKEN_SECRET_EXPIRY_INVALID")
            contents.update({
                "access_token": fresh.access_token,
                "refresh_token": fresh.refresh_token,
                "expires_at": fresh.expires_at.isoformat(),
                "scope": " ".join(fresh.scopes),
            })
            self._save(contents)

        # The token endpoint is pinned to Google, not read from customer
        # metadata. Refuse an expired access token if refresh cannot complete.
        fresh = refresh_credentials(
            creds, token_endpoint=TOKEN_ENDPOINT,
            client_id=client_id, client_secret=client_secret,
            save=save, client=client, attempts=2,
        )
        return fresh.access_token
