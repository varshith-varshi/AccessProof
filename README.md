# AccessProof — Google Workspace and Google Drive RAG Security Gateway

**Production V1 direction: Gateway-only customer integration.** AccessProof
runs a customer-side security Gateway and Guard beside a supported enterprise
RAG deployment. It synchronizes an explicitly approved Google Drive corpus and
Google Workspace employee/group permissions; the Guard enforces Layer 1 before
model context and Layer 2 before releasing a buffered response. Every retrieved
resource must carry independently signed content provenance.

## Supported customer integration

1. An authorized Workspace administrator connects Google Workspace / Drive
   using the server-owned OAuth consent flow and selects an approved root.
2. Directory and Drive ACL synchronization complete and fresh trusted policy is
   installed by a customer-hosted, enrolled AccessProof Guard.
3. The customer registers one AccessProof Gateway application and follows
   Gateway setup in the web-v2 console. The guided installer supports a
   reviewed Docker Compose RAG deployment with signed retrieval manifests.
4. The customer explicitly approves routing the supported application path
   through Gateway; the real employee-facing route is tested for allow, deny,
   provenance forgery and in-flight revocation.
5. Protect is eligible only when all source, Guard, route and policy checks
   pass. Merely deploying the Gateway or receiving a heartbeat is not proof
   of protection.

There is no customer RAG SDK, framework adapter catalog, or TypeScript RAG
SDK in this V1 product. Cryptographic provenance, cached-answer
reauthorization and Layer 1/2 algorithms live in the internal
packages/rag_core package and are used by Gateway. Legacy framework
registrations are retained for historical audit but cannot be newly created
or certified as Protect.

### Explicit limitations

- Gateway is not a transparent proxy for arbitrary customer RAGs. The
  upstream RAG must provide a reviewed, signed retrieval manifest, verified
  employee identity and complete intercepted model/cache return path.
- Native model token streaming, WebSocket responses, tool/agent actions and
  arbitrary background return paths are outside V1 certification.
- Google Drive effective permissions, shared drives, limited folders, live
  revocation latency and customer RAG bypass coverage still require
  authorized real enterprise validation.
- This checkout is not certified for unrestricted enterprise production
  Protect. Local builds and synthetic tests are not live-provider proof.

The repository also retains the earlier permission-regression testing engine,
synthetic canaries, private runner, CLI/CI checks and signed audit reports;
those are supporting internal validation tools, not customer RAG integration
choices.

## Local verification

```bash
cp .env.example .env
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check .
.venv/bin/mypy apps packages connectors integrations
make test
.venv/bin/python scripts/demo.py
.venv/bin/python scripts/soak_mock.py
```

The demo intentionally uses a stale-access window longer than its SLO and therefore produces a measured **FAIL**. A FAIL test outcome is the expected successful demonstration of AccessProof detecting a regression.

For the production-shaped local stack:

```bash
cp .env.example .env
docker compose --profile full up --build
```

Open the web application at `http://localhost:3000`, the API at
`http://localhost:8000`, readiness at `http://localhost:8000/health/ready`,
metrics at `http://localhost:8000/metrics`, and OpenAPI at
`http://localhost:8000/api/v1/openapi.json`.

For the web UI outside Docker:

```bash
cd web-v2
npm ci
npm run lint
npm run typecheck
npm run build
npm run test:e2e
npm run dev
```

The Playwright configuration starts a migrated SQLite API and the built Next.js
server. Install Chromium once with `npx playwright install chromium`.

## CLI

After installing the Python package, run `accessproof --help`. The CLI supports
login/configuration, project listing, run creation and polling, JSON/SARIF report
downloads, and signed-manifest verification. CI exit codes are `0` for PASS, `1`
for a security FAIL, `2` for a blocking inconclusive result, and `3` for an
operational error.

## Scope and private runners

Google Workspace / Drive is the sole customer permission source in production
V1. Other provider connectors remain in legacy/internal code paths but are not
production onboarding choices. Outbound-only private runners support regression
testing; the customer RAG Protect integration is Gateway.

## Troubleshooting

If ports are occupied, set `POSTGRES_PORT`, `REDIS_PORT`, `API_PORT`, or `WEB_PORT`
before running Compose. Check `docker compose --profile full ps`, API readiness,
and `docker compose --profile full logs api worker web` first. More cases are in
`docs/troubleshooting.md`.

## Security boundary

Mutation-capable source connections must be constrained to dedicated customer-authorized test resources. Provider adapters track exact provider IDs and explicit boundaries. Never point mutation testing at arbitrary production content.

## Documentation

- `UPGRADE_AUDIT.md` — resolved and remaining P0/P1 findings
- `IMPLEMENTATION_STATUS.md` — strict implemented/tested/externally-validated matrix
- `FINAL_VALIDATION_REPORT.md` — commands executed and blocked checks
- `FINAL_ARCHITECTURE.md` — current control-plane/runner/engine architecture
- `docs/provider-validation.md` — provider-by-provider validation state
- `docs/oidc-sso.md`, `docs/scim-provisioning.md`, `docs/secret-management.md`, `docs/retention.md` — enterprise operations

Do not describe a connector as real-provider validated unless the corresponding dedicated provider test has actually run.

## Build levels

1. Core engine — locally complete.
2. Provider connector framework — locally complete; real-provider validation pending.
3. Private runner/recovery — locally complete.
4. Security/tenancy — locally complete, including live non-owner PostgreSQL RLS validation.
5. Reporting/CI — locally complete; external pipeline execution pending.
6. Enterprise features — OIDC/SCIM Users+Groups/KMS/retention/alerts/OTLP implemented; SAML deferred.
7. Frontend/UX — lint, typecheck, production build/prerender and Chromium E2E validated locally.
8. Deployment — all four images build; PostgreSQL/Redis/API/worker/web Compose stack validated locally.
9. Real-provider validation — requires dedicated external test tenants.
10. Release freeze — requires real-provider and external infrastructure pilot validation.
