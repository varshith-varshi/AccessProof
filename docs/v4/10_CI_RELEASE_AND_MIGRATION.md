# AccessProof V4 — CI, Release and Migration Gate

**Snapshot:** 2026-10-24 · checkout `ab59ffd` + uncommitted V4 work
**Scope of this change set:** CI targets the active `web-v2` frontend; the
signed-report and Guard-reported-revision migrations; production Compose
environment for `web-v2`. It does **not** deliver a reproducible multi-image
release manifest (F09) or a separate migration job (F10).

## 1. CI jobs as changed

`.github/workflows/ci.yml` now defines four jobs.

| Job | What it runs | What it proves |
|---|---|---|
| `python` | `pip install -e '.[dev]'`, `ruff check .`, `mypy apps packages connectors integrations`, `compileall`, `pytest`, single-head check, blank SQLite `alembic upgrade head` | Python lint/types/tests and that a blank database reaches exactly one head |
| `web` | in `web-v2`: `npm ci`, `lint`, `typecheck`, `build`, Playwright Chromium install, `npm run test:e2e` | The active frontend builds and its 29 Playwright assertions pass against a production standalone build |
| `typescript-sdk` | in `packages/rag-sdk-typescript`: `npm ci`, `npm test` (tsc build + 34 node:test cases) | Customer-side TypeScript SDK compiles and its contract tests pass |
| `containers` | Docker builds for API, worker, runner, Guard, Gateway, `web-v2`; Compose `db`+`redis` smoke | Container definitions still build; infrastructure services start |

Changes from the previous workflow:

- The `web` job no longer installs Python or runs `apps/web`. `apps/web` is
  legacy and is not built or tested by CI.
- `web-v2` is built from its own lockfile (`web-v2/package-lock.json`) with Node
  22; the stale `DATABASE_URL` / `ACCESSPROOF_PUBLIC_APP_URL` / `WEB_ORIGIN`
  environment from the old browser job is gone because the Playwright suite
  mocks the API and the Next standalone server reads no database.
- The container job builds `apps/guard` and `apps/gateway` from the repository
  root (their Dockerfiles copy root `pyproject.toml`/`packages`), and builds
  `web-v2` with `web-v2` as context.
- The TypeScript SDK job is new.

### Local verification of these jobs

| Check | Command | Result |
|---|---|---|
| Frontend lint | `cd web-v2 && npm run lint` | pass |
| Frontend typecheck | `cd web-v2 && npm run typecheck` | pass |
| Frontend production build | run inside Playwright `webServer` | pass |
| Browser E2E | `cd web-v2 && npm run test:e2e` | **29 passed, 1 skipped** (skip is the mobile-only navigation assertion in the desktop project) |
| TypeScript SDK | `cd packages/rag-sdk-typescript && npm test` | **34 passed, 0 failed** |
| Single Alembic head | `alembic heads` | `j4e2f6a8c013 (head)` |
| Blank DB migration | `DATABASE_URL=sqlite:////tmp/ap_v4_migration.db alembic upgrade head` | pass |

Not verified locally: GitHub Actions itself, `ruff`/`mypy`/full `pytest`
results are recorded in `18_FINAL_V4_READINESS_REPORT.md`; Docker image builds
were not run on this host because it has ~7.2 GB free and the builds are not
disk-safe. No claim is made that the `containers` job has executed.

## 2. Migration inventory

- Revision `h2b8d4e6f901` (`migrations/versions/h2b8d4e6f901_control_plane_reports.py`),
  down-revision `g1a7c3d8e9f0`. It creates `control_plane_reports` with an
  organization FK (`ON DELETE CASCADE`), a nullable user FK (`ON DELETE SET
  NULL`), report payload/hash/signature/public-key/manifest columns, and
  indexes on `organization_id` and `report_type`.
- Revision `j4e2f6a8c013`
  (`migrations/versions/j4e2f6a8c013_guard_reported_revisions.py`), down-revision
  `i3c9e5b7d102`. It adds `guard_registrations.active_authorization_revisions_json`
  (`TEXT NOT NULL DEFAULT '{}'`) used for Guard-reported revision
  acknowledgement and lag measurement. Downgrade drops the column; the report
  is recoverable from the next authenticated heartbeat, but historical revision
  lag observations are lost.
- The existing migration test upgrades a legacy database from `c8a38e37eb91`
  to `head`, then asserts the report and evidence tables exist and that
  `test_runs.oracle_canary` remains `NOT NULL`. This guards the historical
  runner-oracle invariant through the new revisions.
- The blank SQLite upgrade above exercises the full chain to
  `j4e2f6a8c013`. PostgreSQL was **not** migrated in this pass (no local
  PostgreSQL service was started); production PostgreSQL migration remains
  unverified.

### Rollback behavior

`downgrade()` drops `control_plane_reports`, destroying all generated evidence
reports. For that reason:

1. Take and verify a database backup before downgrading.
2. Prefer roll-forward with a corrective migration over `alembic downgrade`
   once reports exist.
3. Report signatures remain verifiable offline after export; exported JSON is
   unaffected by a schema downgrade, but rows still in the database are lost.

## 3. Production configuration truth

`docker-compose.production.yml` previously passed `API_URL` and a required
`NEXT_PUBLIC_API_URL` to the web container. `web-v2` does not read those names;
it reads `ACCESSPROOF_API_URL` and `ACCESSPROOF_API_HOST` on the server-side
proxy. The service now receives:

```yaml
ACCESSPROOF_API_URL: http://api:8000
ACCESSPROOF_API_HOST: ${ACCESSPROOF_API_HOST:-api.accessproof.in}
```

`docs/production-deployment.md` documents this so operators do not publish
browser-visible credentials or point the container at the public hostname.
`NEXT_PUBLIC_API_URL` remains in `.env.production.example` for compatibility
with other consumers but is not used by `web-v2`.

No production manifest validation was run against intentionally missing
secrets, and no insecure-default rejection test was added in this pass.

## 4. Open release gates (not delivered)

| Gate | Status | Why it remains open |
|---|---|---|
| F09 immutable release manifest | **OPEN** | No SBOM, image digest pinning, checksums, signature/attestation, or one versioned release set. `docker-compose.ec2.yml` still pins an older frontend tag. |
| F10 separate migration job | **OPEN** | The API service still runs `alembic upgrade head && uvicorn ...` at container start. No backup verification, preflight head check, locking, or rollback/roll-forward drill is wired into deployment. |
| F10 competing/duplicate migrations | **OPEN** | No test starts two migrations concurrently or simulates failure mid-migration. |
| Vulnerability/container/secret scanning | **OPEN** | No supply-chain scanning job was added. |
| PostgreSQL upgrade/downgrade | **OPEN** | Only SQLite was exercised locally. |
| Canary/rollback procedure | **OPEN** | Documented only as a manual operator responsibility; not executed. |

## 5. Release verdict for this change set

The code is suitable for **continued local and CI validation**, not an
enterprise production release. The active frontend and SDK are now tested, the
new migration reaches a single head from both blank and legacy SQLite
databases, and the production web environment matches what `web-v2` reads.
Release reproducibility (F09), migration isolation (F10), PostgreSQL
verification, supply-chain scanning, and HA/DR evidence remain explicit
NO-GO items until executed in an authorized environment.
