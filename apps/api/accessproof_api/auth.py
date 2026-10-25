from __future__ import annotations
from collections.abc import Callable, Iterator

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from fastapi import Cookie, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from apps.api.accessproof_api.db import (
    ApiKey,
    Membership,
    OidcConfiguration,
    Session as DbSession,
    SessionLocal,
    User,
    set_tenant_context,
)
from packages.crypto.secrets import hash_token
from packages.domain.rbac import Permission, Role, allows


@dataclass(slots=True)
class Actor:
    user: User
    membership: Membership
    token: str
    api_key_scopes: frozenset[str] | None = None


def get_db() -> Iterator[OrmSession]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_session(
    db: OrmSession,
    user_id: str,
    ttl_hours: int = 24 * 7,
    *,
    auth_method: str = "password",
    auth_organization_id: str | None = None,
) -> str:
    token = secrets.token_urlsafe(48)
    row = DbSession(
        user_id=user_id,
        token_hash=hash_token(token),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=ttl_hours),
        auth_method=auth_method,
        auth_organization_id=auth_organization_id,
    )
    db.add(row)
    db.commit()
    return token


def _scope_for_request(request: Request) -> str | None:
    path = request.url.path
    method = request.method.upper()
    if path.startswith("/api/v1/projects"):
        return "projects:read" if method == "GET" else "projects:write"
    if path.startswith("/api/v1/runs"):
        return "runs:read" if method == "GET" else "runs:create"
    if path.startswith("/api/v1/reports"):
        return "reports:read"
    if path.startswith("/api/v1/current/reports"):
        # Reading, verifying and downloading signed evidence is available to
        # machine keys; generating a new signed report remains interactive-only.
        return "reports:read" if method in {"GET", "HEAD"} else None
    if path.startswith("/api/v1/sources"):
        return "sources:read" if method == "GET" else "sources:write"
    if path.startswith("/api/v1/targets"):
        return "targets:read" if method == "GET" else "targets:write"
    if path.startswith("/api/v1/suites"):
        return "suites:read" if method == "GET" else "suites:write"
    if path.startswith("/api/v1/releases"):
        return "releases:read" if method == "GET" else "releases:write"
    if path.startswith("/api/v1/runners"):
        return "runners:read" if method == "GET" else "runners:write"
    if path.startswith("/api/v1/audit"):
        return "audit:read"
    if path.startswith("/api/v1/webhooks"):
        return "webhooks:manage"
    if path.startswith("/api/v1/entitlements"):
        return "entitlements:read"
    if path.startswith("/api/v1/api-keys"):
        return "api_keys:manage"
    return None


def current_actor(
    request: Request,
    authorization: str | None = Header(default=None),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-ID"),
    x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    accessproof_session: str | None = Cookie(default=None),
    accessproof_csrf: str | None = Cookie(default=None),
    db: OrmSession = Depends(get_db),
) -> Actor:
    if not x_organization_id:
        raise HTTPException(401, "X-Organization-ID is required")
    set_tenant_context(db, x_organization_id)
    credential_source = "bearer"
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
    elif accessproof_session:
        token = accessproof_session
        credential_source = "cookie"
    else:
        raise HTTPException(401, "Authentication is required")
    if credential_source == "cookie" and request.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
        if (
            not accessproof_csrf
            or not x_csrf_token
            or not secrets.compare_digest(accessproof_csrf, x_csrf_token)
        ):
            raise HTTPException(403, "CSRF token required")
    now = datetime.now(timezone.utc)
    token_digest = hash_token(token)
    sess = db.scalar(select(DbSession).where(DbSession.token_hash == token_digest))
    user = None
    api_key_scopes: frozenset[str] | None = None
    if sess and sess.revoked_at is None:
        expires_at = sess.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at > now:
            user = db.get(User, sess.user_id)
    if user is None:
        key = db.scalar(
            select(ApiKey).where(
                ApiKey.token_hash == token_digest, ApiKey.organization_id == x_organization_id
            )
        )
        if key and key.revoked_at is None:
            key_expiry = key.expires_at
            if (
                key_expiry is None
                or (
                    key_expiry.replace(tzinfo=timezone.utc)
                    if key_expiry.tzinfo is None
                    else key_expiry
                )
                > now
            ):
                user = db.get(User, key.user_id)
                try:
                    api_key_scopes = frozenset(json.loads(key.scopes_json or "[]"))
                except (TypeError, ValueError, json.JSONDecodeError):
                    api_key_scopes = frozenset()
                required_scope = _scope_for_request(request)
                if required_scope is None or (
                    required_scope not in api_key_scopes and "*" not in api_key_scopes
                ):
                    raise HTTPException(
                        403,
                        f"API key scope required: {required_scope or 'interactive-session-only'}",
                    )
                key.last_used_at = now
                db.commit()
    if user is None:
        raise HTTPException(401, "Invalid or expired credential")
    if not user.email_verified:
        raise HTTPException(403, "Email verification is required")
    membership = (
        db.scalar(
            select(Membership).where(
                Membership.user_id == user.id, Membership.organization_id == x_organization_id
            )
        )
        if user
        else None
    )
    if not user or not membership:
        raise HTTPException(403, "Organization membership required")
    # Enforced OIDC applies to interactive sessions for the organization. API
    # keys remain a separately scoped machine-auth mechanism. OWNER retains a
    # password break-glass path to recover a broken IdP configuration.
    if api_key_scopes is None and sess is not None and membership.role != Role.OWNER.value:
        oidc = db.get(OidcConfiguration, x_organization_id)
        if oidc and oidc.enforced:
            if sess.auth_method != "oidc" or sess.auth_organization_id != x_organization_id:
                raise HTTPException(
                    403, detail={"code": "sso_required", "organization_id": x_organization_id}
                )
    return Actor(user=user, membership=membership, token=token, api_key_scopes=api_key_scopes)


def current_user(
    authorization: str | None = Header(default=None),
    accessproof_session: str | None = Cookie(default=None),
    db: OrmSession = Depends(get_db),
) -> User:
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
    elif accessproof_session:
        token = accessproof_session
    else:
        raise HTTPException(401, "Authentication required")
    now = datetime.now(timezone.utc)
    sess = db.scalar(select(DbSession).where(DbSession.token_hash == hash_token(token)))
    if not sess or sess.revoked_at is not None:
        raise HTTPException(401, "Invalid session")
    expiry = (
        sess.expires_at if sess.expires_at.tzinfo else sess.expires_at.replace(tzinfo=timezone.utc)
    )
    if expiry <= now:
        raise HTTPException(401, "Expired session")
    user = db.get(User, sess.user_id)
    if not user:
        raise HTTPException(401, "Invalid session")
    if not user.email_verified:
        raise HTTPException(403, "Email verification is required")
    return user


def require(permission: Permission) -> Callable[..., Actor]:
    def dependency(actor: Actor = Depends(current_actor)) -> Actor:
        role = Role(actor.membership.role)
        if not allows(role, permission):
            raise HTTPException(403, "Insufficient role")
        return actor

    return dependency
