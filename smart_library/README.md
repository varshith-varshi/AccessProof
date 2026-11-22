# Smart Library Management System

A library management system that applies the AccessProof security model to library resources.
Members only see and borrow what their verified identity allows. Every release is checked twice,
revocations take effect before release, and the system **fails closed** when it cannot prove that
access is allowed.

## Features

| Area | What it does |
| --- | --- |
| Catalogue | Search by title, author, ISBN or category; filter by availability |
| Loans | Borrow, renew, return; loan limit (5), due dates (14 days), overdue block |
| Fines | Automatic late fines (0.50 per day, rounded up) |
| Reservations | FIFO queue; a returned copy is held for the next member in line |
| Digital reading | E-book excerpts released only after the Layer 2 check |
| Recommendations | Co-borrowing + favourite categories + popularity, always access-filtered |
| Librarian tools | Add books, overdue report, statistics, audit log, grants, memberships, suspensions |
| Access control | Signed identity, versioned policy, Guard Layer 1 + Layer 2, revocation, fail-closed |

## Security model (from the AccessProof requirements)

1. **Verified identity** – each request carries an HMAC-signed token whose subject is the member's
   immutable id. A bare email or a forged/expired token is rejected (`401`).
2. **Versioned policy** – collections are granted to groups or members. Every grant, membership or
   suspension change creates a new policy revision. Effective access = direct grant OR any group grant.
3. **Guard Layer 1 (before showing)** – search, item lookup and recommendations drop restricted titles.
   A hidden title answers `404`, exactly like a missing one. Each visible item carries a signed
   *attestation* (book, collection, member, revision, 15-minute expiry).
4. **Guard Layer 2 (before release)** – checkout, renew, reserve and digital reading verify the
   attestation, then re-check access against the **current** authoritative policy.
5. **Revocation** – librarian changes are pushed to the Guard at once. A background reconciliation
   also runs every 300 s. Layer 2 reads the authoritative policy, so a revocation between search and
   checkout is blocked even before the Guard syncs.
6. **Fail closed** – unverified identity, stale policy (older than 600 s), a missing or disabled
   Guard, an invalid/expired attestation and an unsupported release path are all denied.
7. **Audit** – every allow and deny decision is logged with its reason and policy revision.

## Run it

```bash
cd smart_library
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://localhost:8000 for the web UI, or http://localhost:8000/docs for the interactive API.
Use the demo sign-in to switch between Alice (Finance), Bob (Faculty), Carol (HR), Dave (Student)
and Libby (Librarian). Set `SLMS_DEMO_LOGIN=0` in production and issue tokens from your identity provider.

```bash
pytest tests
```

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `SLMS_DB_PATH` | `smart_library.db` | SQLite file |
| `SLMS_SECRET_KEY` | `dev-only-change-me` | Signing key for tokens and attestations (change it) |
| `SLMS_TOKEN_TTL` | `3600` | Token lifetime, seconds |
| `SLMS_MAX_POLICY_STALENESS` | `600` | Guard denies if its policy is older than this |
| `SLMS_ACL_SYNC` | `300` | Background policy reconciliation interval |
| `SLMS_LOAN_DAYS` / `SLMS_MAX_LOANS` / `SLMS_FINE_PER_DAY` | `14` / `5` / `0.50` | Lending rules |
| `SLMS_DEMO_LOGIN` | `1` | Enables the demo sign-in endpoint |

## API summary

| Method | Path | Who |
| --- | --- | --- |
| POST | `/auth/demo-login` | anyone (demo only) |
| GET | `/me`, `/me/loans`, `/me/reservations`, `/me/recommendations` | member |
| GET | `/books`, `/books/{id}` | member (Layer 1) |
| POST | `/books/{id}/checkout`, `/books/{id}/reserve`, `/books/{id}/read` | member (Layer 2) |
| POST | `/loans/{id}/renew` (Layer 2), `/loans/{id}/return` | member |
| GET | `/guard/status`, `/health` | anyone |
| POST/GET | `/admin/books`, `/admin/overdue`, `/admin/stats`, `/admin/audit` | librarian |
| POST/DELETE | `/admin/grants`, `/admin/memberships` | librarian |
| POST | `/admin/members/{id}/suspend`, `/admin/members/{id}/reinstate`, `/admin/guard/sync` | librarian |

## Layout

```
smart_library/
  app/
    config.py     settings (SLMS_* env vars)
    identity.py   signed member tokens
    policy.py     versioned policy store + effective-access evaluation
    guard.py      Layer 1 / Layer 2 Guard, attestations, fail-closed, audit
    services.py   catalogue, loans, fines, reservations, recommendations
    main.py       FastAPI routes + background reconciliation
    seed.py       demo members, collections and books
    static/       web UI
  tests/          35 pytest tests
```
