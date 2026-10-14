# AccessProof

AccessProof is a CI/CD and continuous-regression platform for enterprise AI permission propagation. It answers one measurable question: **when access changes at the source, does the connected AI actually follow that change?**

The repository contains a FastAPI control plane, deterministic permission-regression engine, private runner, durable worker/outboxes, provider adapters, CLI/CI integrations, signed reports and a Next.js operator UI.

## What the core flow does

1. Create unique synthetic test content/canary inside an explicitly authorized test boundary.
2. Prove the allowed identity can retrieve it from the connected AI.
3. Prove a denied control identity cannot retrieve it.
4. Persist mutation intent/checkpoint and change source access.
5. Confirm authoritative source ground truth changed.
6. Probe the connected AI repeatedly.
7. Measure last exposure, first denial and stable denial.
8. Compare measured propagation to the configured SLO.
9. Return PASS/FAIL/INCONCLUSIVE/PRECONDITION_FAILURE/ERROR/CANCELED with evidence.
10. Clean up tracked synthetic resources and generate signed reports/CI output.

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
cd apps/web
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

## Providers and private runners

Microsoft 365/SharePoint, Google Drive, Confluence, Slack and Salesforce adapters
are capability-gated and contract-tested. Configure each only against a dedicated
test boundary; see `docs/*-setup.md`. None is real-provider validated without a
customer test tenant. Private endpoints and mTLS targets require the outbound-only
runner described in `docs/private-runner.md`.

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
