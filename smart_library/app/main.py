"""FastAPI application for the Smart Library Management System."""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .clock import Clock
from .config import Settings
from .db import Database
from .demo_data import load_demo_data
from .guard import Guard, GuardError
from .identity import IdentityError, IdentityService
from .policy import PolicyStore
from .seed import seed
from .services import LibraryError, LibraryService

STATIC = Path(__file__).parent / "static"
WEB = Path(__file__).parent / "web"  # built React frontend (npm run build in ../frontend)
# Paths the SPA must never shadow for browser navigation.
NON_SPA_PREFIXES = ("/docs", "/redoc", "/openapi.json", "/assets/", "/api/", "/health", "/guard/")
FAIL_CLOSED_503 = {"guard_unavailable", "policy_stale", "policy_not_installed"}


Sort = Literal["title", "recent", "year", "year_asc", "popular", "author"]
Fmt = Literal["digital", "physical"]


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
    copies: int = Field(default=1, ge=0, le=1000)
    digital_content: str | None = None
    description: str | None = Field(default=None, max_length=4000)
    cover_url: str | None = Field(default=None, max_length=500)


class BookUpdate(BaseModel):
    isbn: str | None = Field(default=None, min_length=1)
    title: str | None = Field(default=None, min_length=1)
    author: str | None = Field(default=None, min_length=1)
    category: str | None = Field(default=None, min_length=1)
    year: int | None = Field(default=None, ge=0, le=3000)
    collection_id: str | None = None
    copies_total: int | None = Field(default=None, ge=0, le=1000)
    description: str | None = Field(default=None, max_length=4000)
    cover_url: str | None = Field(default=None, max_length=500)
    digital_content: str | None = None


DEMO_ROLES = {
    "m-alice": "Finance department — can see finance reports",
    "m-bob": "Faculty — research collection and a direct rare-books grant",
    "m-carol": "Human Resources — can see HR policy documents",
    "m-dave": "Student — general and research collections",
    "m-libby": "Librarian — circulation, inventory, reports and audit",
}


class ApiPrefix:
    """ASGI middleware: /api/<path> is served by the same routes as /<path>, so the browser
    frontend can use a clean /api namespace while existing clients and tests keep working."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["path"].startswith("/api/"):
            scope = dict(scope)
            scope["path"] = scope["path"][4:]
            scope["raw_path"] = scope["path"].encode()
        await self.app(scope, receive, send)


def create_app(settings: Settings | None = None, clock: Clock | None = None, background_sync: bool = True) -> FastAPI:
    settings = settings or Settings()
    clock = clock or Clock()
    db = Database(settings.db_path)
    seed(db)
    store = PolicyStore(db, clock)
    if settings.demo_data and load_demo_data(db, clock.now()):
        store.record_change("demo members added")
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

    app = FastAPI(title="Smart Library Management System", version="2.0.0", lifespan=lifespan)

    # --- frontend (single-page app) --------------------------------------------------------
    # check_dir=False: the mount works even if the frontend is built after the server starts.
    app.mount("/assets", StaticFiles(directory=WEB / "assets", check_dir=False), name="assets")

    def spa_index():
        if (WEB / "index.html").is_file():
            return FileResponse(WEB / "index.html", headers={"Cache-Control": "no-cache"})
        return FileResponse(STATIC / "index.html")

    @app.middleware("http")
    async def spa_navigation(request: Request, call_next):
        """Browser navigations (Accept: text/html) to app routes such as /books or /admin get the SPA;
        API calls (fetch with JSON) reach the API. Authorization is always enforced by the API."""
        path = request.url.path
        if (request.method == "GET" and "text/html" in request.headers.get("accept", "")
                and not path.startswith(NON_SPA_PREFIXES) and "." not in path.rsplit("/", 1)[-1]):
            return spa_index()
        return await call_next(request)
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
        return spa_index()

    @app.get("/favicon.svg", include_in_schema=False)
    def favicon():
        icon = WEB / "favicon.svg"
        if icon.is_file():
            return FileResponse(icon)
        raise HTTPException(404)

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

    @app.get("/auth/demo-members")
    def demo_members():
        """Demo identities for the sign-in screen. Only available while demo sign-in is enabled."""
        if not demo_login:
            raise HTTPException(404)
        out = []
        for m in lib.members_overview():
            out.append({"id": m["id"], "name": m["name"], "role": m["role"], "groups": m["groups"],
                        "active": m["active"], "description": DEMO_ROLES.get(m["id"], ", ".join(m["groups"]))})
        return out

    @app.get("/auth/config")
    def auth_config():
        return {"demo_login": demo_login, "token_ttl_seconds": settings.token_ttl_seconds,
                "loan_days": settings.loan_days, "max_active_loans": settings.max_active_loans,
                "fine_per_day": settings.fine_per_day}

    @app.get("/public/overview")
    def public_overview():
        return lib.public_overview()

    @app.get("/public/books")
    def public_books(sort: Literal["popular", "recent", "title", "year"] = "popular", limit: int = 8):
        return lib.public_books(sort, limit)

    # --- member ----------------------------------------------------------------------
    @app.get("/me")
    def me(m: str = Depends(current_member)):
        return {**lib.member(m), "outstanding_fines": lib.outstanding_fines(m), "librarian": lib.is_librarian(m)}

    @app.get("/me/loans")
    def my_loans(m: str = Depends(current_member)):
        return lib.active_loans(m)

    @app.get("/me/reservations")
    def my_reservations(all: bool = False, m: str = Depends(current_member)):
        return lib.reservations(m, include_closed=all)

    @app.delete("/me/reservations/{reservation_id}")
    def cancel_my_reservation(reservation_id: int, m: str = Depends(current_member)):
        return lib.cancel_reservation(m, reservation_id)

    @app.get("/me/history")
    def my_history(m: str = Depends(current_member)):
        return lib.loan_history(m)

    @app.get("/me/fines")
    def my_fines(m: str = Depends(current_member)):
        return lib.member_fines(m)

    @app.get("/me/activity")
    def my_activity(m: str = Depends(current_member)):
        return lib.activity(m)

    @app.get("/me/access")
    def my_access(m: str = Depends(current_member)):
        return lib.access_summary(m)

    @app.get("/me/recommendations")
    def my_recs(limit: int = 5, m: str = Depends(current_member)):
        return lib.recommendations(m, limit)

    @app.get("/books")
    def books(q: str = "", category: str | None = None, available: bool = False, author: str | None = None,
              format: Fmt | None = None, sort: Sort = "title", m: str = Depends(current_member)):
        return lib.search(m, q, category, available, author, format, sort)

    @app.get("/catalog")
    def catalog(q: str = "", category: str | None = None, available: bool = False, author: str | None = None,
                format: Fmt | None = None, sort: Sort = "title", page: int = 1, page_size: int = 12,
                m: str = Depends(current_member)):
        """Paginated catalogue. Every item passed Guard Layer 1 for the calling member."""
        return lib.catalog(m, q, category or None, available, author or None, format, sort, page, page_size)

    @app.get("/catalog/facets")
    def catalog_facets(m: str = Depends(current_member)):
        return lib.facets(m)

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

    @app.get("/admin/books")
    def inventory(q: str = "", _: str = Depends(librarian)):
        return lib.inventory(q)

    @app.patch("/admin/books/{book_id}")
    def update_book(book_id: str, body: BookUpdate, _: str = Depends(librarian)):
        data = body.model_dump(exclude_unset=True)
        result = lib.update_book(book_id, data)
        if "collection_id" in data:
            guard.sync()  # moving a title between collections changes who may see it
        return result

    @app.get("/admin/members")
    def members(q: str = "", _: str = Depends(librarian)):
        return lib.members_overview(q)

    @app.get("/admin/loans")
    def all_loans(status: Literal["all", "open", "active", "due_soon", "overdue", "returned"] = "all",
                  q: str = "", page: int = 1, page_size: int = 20, _: str = Depends(librarian)):
        return lib.all_loans(status, q, page, page_size)

    @app.get("/admin/reservations")
    def all_reservations(status: Literal["open", "all", "waiting", "ready", "fulfilled", "cancelled"] = "open",
                         _: str = Depends(librarian)):
        return lib.all_reservations(status)

    @app.delete("/admin/reservations/{reservation_id}")
    def admin_cancel_reservation(reservation_id: int, librarian_id: str = Depends(librarian)):
        return lib.cancel_reservation(librarian_id, reservation_id, as_librarian=True)

    @app.get("/admin/fines")
    def fines(_: str = Depends(librarian)):
        return lib.fines_overview()

    @app.get("/admin/reports")
    def reports(months: int = 6, _: str = Depends(librarian)):
        return lib.reports(max(1, min(months, 24)))

    @app.get("/admin/access")
    def access(_: str = Depends(librarian)):
        return {**lib.access_overview(), "guard": guard.status()}

    @app.get("/admin/audit/search")
    def audit_search(member: str | None = None, action: str | None = None,
                     decision: Literal["allow", "deny", "info"] | None = None, since: float | None = None,
                     until: float | None = None, page: int = 1, page_size: int = 25, _: str = Depends(librarian)):
        return lib.audit_search(member or None, action or None, decision, since, until, page, page_size)

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

    app.add_middleware(ApiPrefix)
    return app


app = create_app() if os.getenv("SLMS_NO_AUTOAPP") != "1" else None
