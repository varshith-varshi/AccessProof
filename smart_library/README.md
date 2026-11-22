# Smart Library Management System

A full-stack university library platform: a public landing page, a member portal (catalogue,
borrowing, reservations, e-book reader, recommendations, fines) and a librarian console
(inventory, members, circulation, reports, audit log, access policy).

It applies the **AccessProof** security model to library resources. Members only see and borrow
what their verified identity allows, every release is checked twice, revocations take effect
before release, and the system **fails closed** when it cannot prove that access is allowed.

| | |
| --- | --- |
| Backend | Python 3.12+, FastAPI 0.128, SQLite, pytest |
| Frontend | React 18, TypeScript, Vite 6, Tailwind CSS 4, TanStack Query, React Router, Recharts, Lucide |
| Tests | 69 backend tests (pytest) · 16 end-to-end browser tests (Playwright) |

## Quick start (Ubuntu)

```bash
cd smart_library
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open **http://localhost:8000**. The built frontend ships in `app/web/`, so Node.js is not needed
just to run the site. The interactive API documentation is at http://localhost:8000/docs.

### Frontend development (hot reload)

Requires Node.js 20+.

```bash
./dev.sh          # API on :8000 + Vite on http://localhost:5173 (proxies /api to :8000)
```

or manually:

```bash
cd frontend
npm install
npm run dev       # http://localhost:5173
npm run build     # type-checks, then writes the production build to ../app/web
```

## Demo accounts

Sign-in is a clearly labelled **Demo Mode**: pick an identity and the server issues a signed,
expiring token for it. It is not production authentication (see *Production identity* below).

| Member | Groups | What to try |
| --- | --- | --- |
| **Alice** | finance | Sees *Finance reports*; has a loan that is due soon |
| **Bob** | faculty | Research collection + a direct grant to *Rare books*; holds the only copy of *Nineteen Eighty-Four* |
| **Carol** | hr | Sees *HR policy documents*; has an **overdue** loan, so borrowing is blocked |
| **Dave** | students | General + research; waiting in the queue for *Nineteen Eighty-Four*; has past fines |
| **Erin, Farid, Hiro** | students | Extra demo readers (circulation history) |
| **Grace** | faculty | Extra demo reader |
| **Libby** | librarians | Librarian console at `/admin` |

### Demonstration scenarios

1. **Successful borrowing:** Dave opens *Structure and Interpretation of Computer Programs* and clicks **Borrow**.
2. **Unauthorised access:** Bob searches “Forecast”. Nothing is found, and `/books/b-008` answers *Book not found*.
3. **Reservation:** Erin opens *Nineteen Eighty-Four* (all copies out) and clicks **Reserve** to join the queue at #2.
4. **Return:** a member returns a loan from **My Books**. If someone is waiting, the copy goes on the hold shelf for them.
5. **Renewal:** Dave renews *Introduction to Linear Algebra*. Bob cannot renew *Nineteen Eighty-Four* because Dave is waiting.
6. **Access revocation:** Alice opens *FY2027 Library Budget*. In another browser, Libby removes Alice from
   **finance** in *Access & Settings*. Alice clicks **Borrow** and is refused (Layer 2), and the title disappears from her search (Layer 1).
7. **Overdue handling:** Carol's dashboard and **Fines** page show the accruing fine. She cannot borrow until she returns the book.
8. **Librarian reporting:** Libby's dashboard, **Reports** and **Audit Logs** pages, built from live database rows.

## Features

**Public site:** hero, feature highlights, popular and recently added titles, and live statistics.
Only collections open to everyone appear here, as metadata only. No attestations or content are exposed.

**Member portal**

| Page | Route | What it does |
| --- | --- | --- |
| Dashboard | `/dashboard` | Loans, reservations, upcoming returns, fines, recent activity, quick actions, recommendations |
| Catalogue | `/books` | Debounced search (title, author, ISBN, category, description keywords); filters for category, author, availability and format; 6 sort orders; pagination |
| Book details | `/books/:id` | Metadata, stock, personal borrowing eligibility, borrow / reserve / read |
| My books | `/my-books` | Current loans with *Active / Due soon / Overdue* badges, renew, return; loan history |
| Reservations | `/reservations` | Queue position, ready-for-pickup notice, cancel, past reservations |
| Digital library | `/ebooks`, `/ebooks/:id/read` | Reader with font size, light / sepia / dark pages, section navigation, progress, keyboard arrows |
| Recommendations | `/recommendations` | Co-borrowing → favourite categories → popularity, each with a visible reason |
| Fines | `/fines` | Outstanding and accruing fines, overdue books, fine history |
| Profile | `/profile` | Identity, groups and the collections the member may use (and why) |

**Librarian console** (`/admin`, librarian role required)

| Page | Route | What it does |
| --- | --- | --- |
| Dashboard | `/admin` | Totals, available copies, loans, members, reservations, overdue; four charts |
| Inventory | `/admin/books` | Add and edit titles with validation. Stock edits cannot drop below copies on loan or on hold |
| Members | `/admin/members` | Searchable directory with loans, reservations and fines; suspend or reinstate |
| Borrowing records | `/admin/loans` | All loans, filtered by status, searchable, paginated |
| Reservations | `/admin/reservations` | All queues by status; cancel (held copy passes to the next member) |
| Fines | `/admin/fines` | Outstanding and accruing totals, overdue list, member summary, fine records |
| Reports | `/admin/reports` | Monthly borrowing, reservation trends, categories, loan status, top titles, allow/deny decisions |
| Audit logs | `/admin/audit` | Filter by member, action, decision and date range; paginated; expandable details |
| Access & settings | `/admin/settings` | Guard status, policy sync, collection grants, group memberships, revision history, lending rules |

There are also 403 and 404 pages, and an error boundary.

**Not implemented:** online fine payment (clearly labelled; nothing is simulated), deleting
titles (avoids orphaning loan and audit history), email/SMS reminders, and production SSO.

## Security model (from the AccessProof requirements)

1. **Verified identity:** each request carries an HMAC-signed token whose subject is the member's
   immutable id. A bare email, or a forged or expired token, is rejected (`401`).
2. **Versioned policy:** collections are granted to groups or members. Every grant, membership or
   suspension change creates a new policy revision. Effective access = direct grant OR any group grant.
3. **Guard Layer 1 (before showing):** search, catalogue pages, facets, item lookup and
   recommendations drop restricted titles. A hidden title answers `404`, exactly like a missing one.
   Each visible item carries a signed *attestation* (book, collection, member, revision, 15-minute expiry).
4. **Guard Layer 2 (before release):** checkout, renew, reserve and digital reading verify the
   attestation, then re-check access against the **current** authoritative policy. The frontend
   fetches a fresh attestation immediately before every action, and e-book content is never cached.
5. **Revocation:** librarian changes are pushed to the Guard at once, and a background
   reconciliation also runs every 300 s. A revocation between search and checkout is blocked.
6. **Fail closed:** unverified identity, stale policy (older than 600 s), a missing or disabled
   Guard, an invalid or expired attestation, and an unsupported release path are all denied (`401` / `403` / `503`).
7. **Audit:** every allow and deny decision, plus loans, returns, renewals, reservations,
   cancellations and business-rule denials, is logged with its reason and policy revision.
   SQLite triggers make `audit_log` **append-only**: `UPDATE` and `DELETE` are rejected.
8. **Backend enforcement:** route guards in the React app are for user experience only. Every
   protected endpoint enforces identity and role on the server.

### Production identity

Set `SLMS_DEMO_LOGIN=0` to disable `/auth/demo-login` and `/auth/demo-members`. Replace them with
the institution's OIDC provider (for example Entra ID or Google Workspace): after the OIDC code
flow, map the provider's immutable subject to a member id and call `IdentityService.issue()`
(or verify the provider's JWT directly in `current_member`). Sync groups from the campus directory
into `memberships`. Change `SLMS_SECRET_KEY`.

## Database

SQLite, file set by `SLMS_DB_PATH` (default `smart_library.db`, created on first start).

* **10 original tables:** members, groups, memberships, collections, grants, policy_revisions,
  books, loans, reservations, audit_log.
* **Safe, idempotent migrations** run at start-up (`app/db.py`). They add `books.description`,
  `books.cover_url`, `books.added_at`, `loans.renewals`, `reservations.updated_at`, an `app_meta`
  table, indexes, and the append-only audit triggers. Nothing is dropped or rewritten.
* **Transactions:** checkout, return, renewal and reservation cancellation each run in one
  transaction, and stock is updated with guarded `UPDATE … WHERE copies_available > 0`.
* **Demo data** (`app/demo_data.py`) adds 28 titles across Computer Science, Artificial
  Intelligence, Machine Learning, Mathematics, Physics, Literature, History, Business, Engineering
  and Science, plus 4 readers and 6 months of circulation history. It is safe to rerun: rows are
  inserted with `INSERT OR IGNORE`, metadata is only filled where empty, and history is written once.
  It runs on start-up unless `SLMS_DEMO_DATA=0`, and can also be run with `python -m app.demo_data`.
* **E-books** are public-domain opening passages (Shelley, Dickens, Melville, Sun Tzu/Giles,
  Adam Smith, Darwin) or original study material written for this project. No copyrighted text is included.

To start fresh, stop the server and delete `smart_library.db`.

## Running the tests

```bash
# Backend (69 tests)
source .venv/bin/activate
pytest tests

# End-to-end (16 tests). Starts its own server on :8765 with a throwaway database.
cd frontend
npx playwright test
```

The e2e tests cover the landing page, sign-in, search, filters and pagination, hidden restricted
titles, borrow, return, renew, reserve and cancel, revocation between discovery and borrowing,
overdue handling, the e-book reader (including a refused restricted e-book), librarian role
isolation, dashboards, inventory validation, audit filtering, access settings and mobile
navigation (no horizontal overflow at phone width).

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `SLMS_DB_PATH` | `smart_library.db` | SQLite file |
| `SLMS_SECRET_KEY` | `dev-only-change-me` | Signing key for tokens and attestations (change it) |
| `SLMS_TOKEN_TTL` | `3600` | Token lifetime, seconds |
| `SLMS_MAX_POLICY_STALENESS` | `600` | Guard denies if its policy is older than this |
| `SLMS_ACL_SYNC` | `300` | Background policy reconciliation interval |
| `SLMS_LOAN_DAYS` / `SLMS_MAX_LOANS` / `SLMS_FINE_PER_DAY` | `14` / `5` / `0.50` | Lending rules |
| `SLMS_DUE_SOON_DAYS` | `3` | A loan is “due soon” within this many days |
| `SLMS_DEMO_LOGIN` | `1` | Enables demo sign-in |
| `SLMS_DEMO_DATA` | `1` | Loads the extended demo catalogue and history |

Ports: 8000 (app and API), 5173 (Vite dev server, development only), 8765 (e2e test server).

## API summary

The frontend calls the API under `/api/…`. The same routes also answer without the prefix, so
existing clients keep working. Browser navigation to an app route (for example `/books`) is
served the single-page app, while JSON requests reach the API.

| Method | Path | Who |
| --- | --- | --- |
| POST / GET | `/auth/demo-login`, `/auth/demo-members`, `/auth/config` | anyone (demo only) |
| GET | `/public/overview`, `/public/books` | anyone (open collections, metadata only) |
| GET | `/me`, `/me/loans`, `/me/history`, `/me/reservations`, `/me/fines`, `/me/activity`, `/me/access`, `/me/recommendations` | member |
| DELETE | `/me/reservations/{id}` | member (own reservation) |
| GET | `/books`, `/books/{id}`, `/catalog`, `/catalog/facets` | member (Layer 1) |
| POST | `/books/{id}/checkout`, `/books/{id}/reserve`, `/books/{id}/read`, `/loans/{id}/renew` | member (Layer 2) |
| POST | `/loans/{id}/return` | member |
| GET | `/guard/status`, `/health` | anyone |
| GET | `/admin/stats`, `/admin/reports`, `/admin/books`, `/admin/members`, `/admin/loans`, `/admin/reservations`, `/admin/fines`, `/admin/overdue`, `/admin/access`, `/admin/audit`, `/admin/audit/search` | librarian |
| POST / PATCH / DELETE | `/admin/books`, `/admin/books/{id}`, `/admin/reservations/{id}` | librarian |
| POST / DELETE | `/admin/grants`, `/admin/memberships` | librarian (new policy revision) |
| POST | `/admin/members/{id}/suspend`, `/admin/members/{id}/reinstate`, `/admin/guard/sync` | librarian |

## Layout

```
smart_library/
  app/
    config.py      settings (SLMS_* env vars)
    identity.py    signed member tokens
    policy.py      versioned policy store + effective-access evaluation
    guard.py       Layer 1 / Layer 2 Guard, attestations, fail-closed, audit
    services.py    catalogue, loans, fines, reservations, recommendations, reports, inventory
    main.py        FastAPI routes, /api prefix, SPA serving, background reconciliation
    db.py          schema + idempotent migrations + append-only audit triggers
    seed.py        base demo members, collections and 12 books (used by the original tests)
    demo_data.py   extended catalogue, extra readers, circulation history
    web/           built frontend (generated by `npm run build`)
    static/        fallback page shown if the frontend has not been built
  frontend/
    src/lib/         API client, auth context, action hooks, formatting
    src/components/  UI kit (Button, Badge, StatCard, DataTable, Modal, Toast, Pagination, …), book covers
    src/layouts/     public navbar/footer, app shell with sidebar, route guards
    src/pages/       landing, login, member pages, admin pages
    e2e/             Playwright tests
  tests/           pytest: access control, library rules, extended API
  dev.sh           start API + Vite together
```

## Troubleshooting

* **`pytest` crashes with `unknown hook 'pytest_launch_collect_makemodule'`:** a ROS installation
  injects pytest plugins. Run `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests`.
* **Blank page at http://localhost:8000:** the frontend is not built. Run `cd frontend && npm install && npm run build`.
* **`503 policy_stale` errors:** the Guard refuses to decide on a policy older than 10 minutes.
  This is deliberate fail-closed behaviour. The background sync normally prevents it, or use
  *Sync policy now* in *Access & Settings*.
* **Signed out unexpectedly:** tokens expire after an hour (`SLMS_TOKEN_TTL`). Sign in again.
* **Playwright cannot find a browser:** run `npx playwright install chromium`, or set
  `PW_CHROMIUM_PATH` to an existing Chromium binary.
* **Port 8000 in use:** `uvicorn app.main:app --port 8001`, then open that port.
