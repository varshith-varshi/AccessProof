# AccessProof upgrade audit

Status date: 2026-10-02

## Architecture inspected

The repository is a modular FastAPI/SQLAlchemy control plane with a durable worker,
outbound private runner, provider connector SDK/factory, deterministic permission
regression engine, Next.js UI, CLI, CI integrations, Alembic migrations and
PostgreSQL/Redis Compose deployment. The supplied directory is an extracted tree
without Git metadata. All application, package, connector, integration, migration,
test, script, infrastructure, workflow and documentation files were inventoried;
the existing modular architecture was retained.

## Initial findings

- Prior documents claimed 121 tests passed, but frontend dependency installation,
  lint, typecheck, production build, Playwright, Docker and live PostgreSQL RLS had
  not run in that environment.
- `package-lock.json` and ESLint configuration were missing while CI claimed to run
  reproducible frontend checks.
- Pydantic email fields made API import fail in a clean environment because
  `email-validator` was undeclared.
- Strict MyPy reported 214 errors and Ruff initially reported 460 findings.
- The OIDC completion route used `useSearchParams` without a Suspense boundary;
  several forms lacked usable label associations and effect patterns failed the
  current React/Next lint rules.
- Old Playwright and ESLint dependencies carried known advisories.
- The generic AI target could interpret redirects, malformed JSON, absent answer
  mappings or malformed evidence channels as available clean responses. That could
  turn uncertainty into a false denial.
- Required ERROR/CANCELED scenarios could escape release blocking when ordinary
  inconclusive outcomes were configured as non-blocking; an empty decision set
  could return PASS.
- Resource deletion needed an explicit pre-call destructive marker so an ambiguous
  provider response could not cause generic cleanup to issue a second delete.
- Docker build context did not explicitly exclude `.env`, databases and generated
  local artifacts. Compose published ports on all interfaces and the runner image
  had no guaranteed writable state directory after dropping privileges.
- Documentation advertised direct grant/group-add propagation although the engine
  deliberately rejects those inverse transitions as unsupported.

## Fixes completed

- Added all clean-install Python dependencies, frontend lockfile and flat ESLint
  configuration; upgraded vulnerable development dependencies to audited versions.
- Formatted and typed the Python source without weakening strict MyPy. Corrected
  concrete type narrowing and provider-response validation issues found along the way.
- Fixed Suspense/search-parameter pages, effect loading paths, form labels and
  production Playwright startup. CI now uses `npm ci`.
- Hardened HTTP targets to GET/POST, valid credential-free HTTP(S) URLs, strict 2xx
  object contracts, string answer/evidence types and conservative unavailable
  outcomes for redirects and malformed responses. Added regression coverage.
- Corrected release decisions for ERROR, CANCELED and empty releases with tests.
- Added destructive resource-delete intent tracking and a regression proving an
  ambiguous delete request is not replayed by generic cleanup.
- Added `.gitignore`/`.dockerignore`, lockfile-based web builds, missing API image
  integration sources, writable non-root runner state, loopback host bindings and
  configurable Compose ports.
- Built all images and validated the live PostgreSQL/Redis/API/worker/web stack.
- Validated blank and upgrade PostgreSQL migrations plus tenant filtering with a
  non-owner RLS role.
- Updated README, architecture, status and validation documents to match measured
  results and to mark grant/add propagation and all real-provider work honestly.

## Validation baseline

- 131/131 Python tests pass.
- Ruff, strict MyPy across 67 source files and compileall pass.
- npm audit reports zero known vulnerabilities; frontend lint, typecheck, production
  build/prerender and 3/3 Chromium E2E tests pass.
- One Alembic head; blank PostgreSQL and `8f21c6d4aa10` upgrade paths pass.
- Live non-owner PostgreSQL RLS tenant switching exposes only the selected tenant.
- API, worker, runner and web images build and run as non-root identities.
- PostgreSQL, Redis, API, worker and web services run together; readiness is healthy.
- The 120-run soak reports 30 PASS/90 expected FAIL with zero leaks or duplicates.

## Remaining release blockers

Real-provider credentials and dedicated test tenants were not supplied for
Microsoft 365, Google Workspace, Atlassian, Slack or Salesforce. Real OIDC, AWS
KMS, SMTP, OTLP and external CI execution also require deployment-specific accounts.
SAML remains deferred pending a vetted implementation. These are externally
unvalidated and are not represented as passed.
