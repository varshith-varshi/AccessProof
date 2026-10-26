# AccessProof final validation report

Status date: 2026-10-02

## Conclusion

AccessProof is locally validated across Python, Next.js, Chromium, PostgreSQL,
Redis and Docker. It is ready for real-provider pilot validation. Microsoft 365,
Google Workspace, Atlassian, Slack and Salesforce were not exercised with real
credentials, so the repository is not described as universally production-ready.

## Environment

- Ubuntu Linux 6.8
- Python 3.12.3 in `.venv`
- Node 22.22.3 and npm 10.9.8
- Docker 29.1.3 and Compose 2.40.3
- PostgreSQL 17 and Redis 7 in Docker

## Executed validation

```bash
.venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check .
.venv/bin/mypy apps packages connectors integrations
.venv/bin/python -m compileall -q apps packages connectors integrations scripts migrations
.venv/bin/python -m pytest -q
.venv/bin/python scripts/demo.py
.venv/bin/python scripts/soak_mock.py

cd apps/web
npm ci
npm audit --audit-level=high
npm run lint
npm run typecheck
npm run build
npm run test:e2e

docker compose --profile full build
docker compose --profile runner build runner
docker compose --profile full up -d
```

Results:

- Python tests: 131/131 passed (unit, integration, security and connector contract).
- Ruff: pass.
- strict MyPy: 67 source files, no issues.
- Python compileall: pass.
- npm audit: zero known vulnerabilities.
- ESLint and TypeScript: pass.
- Next.js 16 production build and static prerender: pass.
- Playwright Chromium: 3/3 pass against a migrated API and production web server.
- Deterministic demo: expected FAIL, stable denial 110s versus 30s SLO.
- Mock soak: 120 runs; 30 PASS, 90 expected FAIL, zero resource/helper leaks,
  and zero duplicate mutations across six loss-of-access transitions.

## Database

- Alembic has one head: `af42d9c7310e`.
- A blank PostgreSQL 17 database upgraded to head successfully.
- A separate PostgreSQL database upgraded through `8f21c6d4aa10` and then to
  `af42d9c7310e` successfully.
- A non-owner runtime role was granted table SELECT only. With RLS bypass off,
  switching `accessproof.organization_id` exposed only that organization's rows
  for each of two tenants. Live RLS enforcement therefore passed.
- The automated SQLite blank/upgrade migration test also passes.

## Docker and runtime

API, worker, runner and web images built successfully. Image runtime users are
`10001:10001`, `10001:10001`, `10001:10001`, and `node`, respectively. The
PostgreSQL/Redis/API/worker/web Compose stack is running and healthy on the audit
ports. API readiness reports both database and Redis as healthy; the web login
page returns 200. Runner leasing/execution/recovery is covered by the local
integration suite because live registration credentials are deployment data.

## Security fixes and checks

- Added the missing `email-validator` runtime dependency required by API schemas.
- Cloud HTTP targets remain public-HTTPS-only with DNS resolution and IP pinning.
- AI target redirects, non-2xx responses, malformed/non-object JSON, missing answer
  mappings and malformed evidence channels now return unavailable observations;
  none can be misclassified as a clean denial.
- HTTP targets accept only GET/POST and reject URL credentials and unsafe schemes.
- Release decisions now block ERROR and CANCELED required scenarios even when an
  operator elects not to block ordinary inconclusive outcomes; an empty release is
  INCONCLUSIVE rather than PASS.
- Resource deletion records the destructive boundary before the provider call.
  Ambiguous delete outcomes are not blindly replayed by generic cleanup and are
  surfaced for durable reconciliation.
- Browser Suspense boundaries, effect behavior, form labels and dependency audit
  findings were repaired.
- Docker build context excludes `.env`, local databases, virtual environments,
  caches and frontend build outputs. Published host ports bind to loopback by default.
- Automated coverage verifies CSRF/session behavior, scoped API keys, tenant
  authorization, report tamper detection, audit immutability, webhook signatures,
  SSRF controls, runner recovery and cleanup durability.

## Provider status and external validation

Microsoft 365/SharePoint, Google Drive, Confluence, Slack and Salesforce adapters
are implemented for their documented safe subsets and are contract-tested with
mocks. Real-provider validation is **NO** for all five because no dedicated test
tenants or credentials were supplied. Real OIDC IdP, AWS KMS, production SMTP,
OTLP backend and external GitHub/GitLab pipeline execution also remain unvalidated.
Exact provider pilot procedures are in `docs/provider-validation.md` and the
provider-specific setup guides.

## Known product limits

- Direct grant and group-member addition are declared scenario vocabulary but are
  not implemented by the loss-of-access propagation engine; capability planning
  returns an unsupported/inconclusive result rather than running the wrong mutation.
- SAML is deferred until a vetted SAML/XML-signature implementation is selected.
- Kubernetes/Helm is deliberately outside the current architecture.

## Deliverable

The corrected source tree is `/home/white-devil/Downloads/accessproof/f2`. A
secret-free release archive is written to
`/home/white-devil/Downloads/accessproof/AccessProof-validated-2026-10-02.tar.gz`.
The archive excludes local `.env`, databases, virtual environments, dependencies,
caches and generated build output.
