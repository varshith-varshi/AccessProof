"""FastAPI application for the Smart Library Management System."""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from .clock import Clock
from .config import Settings
from .db import Database
from .guard import Guard, GuardError
from .identity import IdentityError, IdentityService
from .policy import PolicyStore
from .seed import seed
from .services import LibraryError, LibraryService

STATIC = Path(__file__).parent / "static"
FAIL_CLOSED_503 = {"guard_unavailable", "policy_stale", "policy_not_installed"}


class AttestationBody(BaseModel):
    attestation: str | None = None


class LoginBody(BaseModel):
    member_id: str


class GrantBody(BaseModel):
    collection_id: str
    principal_type: Literal["member", "group"]
    principal_id: str


class MembershipBody(BaseModel):
    member_id: str
    group_id: str


class NewBook(BaseModel):
    id: str
    isbn: str
    title: str
    author: str
    category: str
    year: int | None = None
    collection_id: str
    copies: int = Field(default=1, ge=1)
    digital_content: str | None = None


def create_app(settings: Settings | None = None, clock: Clock | None = None, background_sync: bool = True) -> FastAPI:
    settings = settings or Settings()
    clock = clock or Clock()
    db = Database(settings.db_path)
    seed(db)
    store = PolicyStore(db, clock)
    guard = Guard(db, store, clock, settings.secret_key, settings.max_policy_staleness_seconds,
                  settings.attestation_ttl_seconds)
    guard.sync()
    identity = IdentityService(settings.secret_key, settings.token_ttl_seconds, clock)
    lib = LibraryService(db, store, guard, clock, settings)
    demo_login = os.getenv("SLMS_DEMO_LOGIN", "1") == "1"

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        task = None
        if background_sync:
            async def reconcile() -> None:
                while True:
                    await asyncio.sleep(settings.acl_sync_interval_seconds)
                    if guard.enabled:
                        guard.sync()
            task = asyncio.create_task(reconcile())
        yield
        if task:
            task.cancel()

    app = FastAPI(title="Smart Library Management System", version="1.0.0", lifespan=lifespan)
    app.state.lib, app.state.guard, app.state.identity, app.state.clock = lib, guard, identity, clock

    # --- error mapping (fail closed) -----------------------------------------------------
    @app.exception_handler(GuardError)
    async def _guard_err(_: Request, exc: GuardError):
        status = 503 if exc.code in FAIL_CLOSED_503 else 403
        return JSONResponse({"error": exc.code, "detail": exc.message}, status_code=status)

    @app.exception_handler(LibraryError)
    async def _lib_err(_: Request, exc: LibraryError):
        return JSONResponse({"error": exc.code, "detail": exc.message}, status_code=exc.status)

    def current_member(authorization: str | None = Header(default=None)) -> str:
        token = authorization.removeprefix("Bearer ").strip() if authorization else None
        try:
            member_id = identity.verify(token).member_id
        except IdentityError as exc:
            guard.audit(None, "authenticate", None, "deny", f"unverified identity: {exc}", guard.installed_revision)
            raise HTTPException(401, detail={"error": "unverified_identity", "detail": str(exc)}) from exc
        if not lib.member(member_id)["active"]:
            raise HTTPException(403, detail={"error": "member_suspended", "detail": "membership suspended"})
        return member_id

    def librarian(member_id: str = Depends(current_member)) -> str:
        if not lib.is_librarian(member_id):
            raise HTTPException(403, detail={"error": "not_librarian", "detail": "librarian role required"})
        return member_id

    # --- public ----------------------------------------------------------------------
    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/guard/status")
    def guard_status():
        return guard.status()

    @app.post("/auth/demo-login")
    def demo(body: LoginBody):
        """Stand-in for the organisation's OIDC provider. Disable with SLMS_DEMO_LOGIN=0."""
        if not demo_login:
            raise HTTPException(404)
        lib.member(body.member_id)
        return {"access_token": identity.issue(body.member_id), "token_type": "bearer"}

    # --- member ----------------------------------------------------------------------
    @app.get("/me")
    def me(m: str = Depends(current_member)):
        return {**lib.member(m), "outstanding_fines": lib.outstanding_fines(m), "librarian": lib.is_librarian(m)}

    @app.get("/me/loans")
    def my_loans(m: str = Depends(current_member)):
        return lib.active_loans(m)

    @app.get("/me/reservations")
    def my_reservations(m: str = Depends(current_member)):
        return lib.reservations(m)

    @app.get("/me/recommendations")
    def my_recs(limit: int = 5, m: str = Depends(current_member)):
        return lib.recommendations(m, limit)

    @app.get("/books")
    def books(q: str = "", category: str | None = None, available: bool = False, m: str = Depends(current_member)):
        return lib.search(m, q, category, available)

    @app.get("/books/{book_id}")
    def book(book_id: str, m: str = Depends(current_member)):
        return lib.get_book(m, book_id)

    @app.post("/books/{book_id}/checkout")
    def checkout(book_id: str, body: AttestationBody, m: str = Depends(current_member)):
        return lib.checkout(m, book_id, body.attestation)

    @app.post("/books/{book_id}/reserve")
    def reserve(book_id: str, body: AttestationBody, m: str = Depends(current_member)):
        return lib.reserve(m, book_id, body.attestation)

    @app.post("/books/{book_id}/read")
    def read(book_id: str, body: AttestationBody, m: str = Depends(current_member)):
        return lib.read_digital(m, book_id, body.attestation)

    @app.post("/loans/{loan_id}/renew")
    def renew(loan_id: int, body: AttestationBody, m: str = Depends(current_member)):
        return lib.renew(m, loan_id, body.attestation)

    @app.post("/loans/{loan_id}/return")
    def give_back(loan_id: int, m: str = Depends(current_member)):
        return lib.return_book(m, loan_id)

    # --- librarian -------------------------------------------------------------------
    @app.post("/admin/books", status_code=201)
    def add_book(body: NewBook, _: str = Depends(librarian)):
        return lib.add_book(body.model_dump())

    @app.get("/admin/overdue")
    def overdue(_: str = Depends(librarian)):
        return lib.overdue_report()

    @app.get("/admin/stats")
    def stats(_: str = Depends(librarian)):
        return lib.statistics()

    @app.get("/admin/audit")
    def audit(limit: int = 100, _: str = Depends(librarian)):
        return lib.audit(limit)

    def _changed(rev: int) -> dict:
        guard.sync()  # push the new revision to the Guard immediately
        return {"policy_revision": rev, "guard_installed_revision": guard.installed_revision}

    @app.post("/admin/grants")
    def add_grant(body: GrantBody, _: str = Depends(librarian)):
        return _changed(lib.store.grant(body.collection_id, body.principal_type, body.principal_id))

    @app.delete("/admin/grants")
    def del_grant(body: GrantBody, _: str = Depends(librarian)):
        return _changed(lib.store.revoke(body.collection_id, body.principal_type, body.principal_id))

    @app.post("/admin/memberships")
    def add_membership(body: MembershipBody, _: str = Depends(librarian)):
        return _changed(lib.store.add_membership(body.member_id, body.group_id))

    @app.delete("/admin/memberships")
    def del_membership(body: MembershipBody, _: str = Depends(librarian)):
        return _changed(lib.store.remove_membership(body.member_id, body.group_id))

    @app.post("/admin/members/{member_id}/suspend")
    def suspend(member_id: str, _: str = Depends(librarian)):
        lib.member(member_id)
        return _changed(lib.store.set_member_active(member_id, False))

    @app.post("/admin/members/{member_id}/reinstate")
    def reinstate(member_id: str, _: str = Depends(librarian)):
        lib.member(member_id)
        return _changed(lib.store.set_member_active(member_id, True))

    @app.post("/admin/guard/sync")
    def force_sync(_: str = Depends(librarian)):
        return {"installed_revision": guard.sync()}

    return app


app = create_app() if os.getenv("SLMS_NO_AUTOAPP") != "1" else None
