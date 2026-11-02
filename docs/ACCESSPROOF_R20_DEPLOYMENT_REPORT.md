# AccessProof r20 deployment report — 2026-11-02

## Verdict: **DEPLOYMENT_BLOCKED**

Production was **not changed**. From this engineering environment:

* `https://api.accessproof.in` and `https://app.accessproof.in` were denied by the
  session network policy (proxy CONNECT refused).
* AWS endpoints were reachable, but the container's AWS credentials were rejected
  by STS (`InvalidClientTokenId`). SSM, EC2 and S3 could not be used, and no
  valid credential exists in this environment to verify account `102076848988`.
* No Remote Control computer was connected, so the operator workstation
  (the local repository and its working AWS access) was not reachable.

The live audit (§11), live deployment (§18), production verification (§19–20)
and real-customer regression (§21) were **not performed**. No result below
describes production.

## A. Source version

| | |
|---|---|
| Repository | github.com/varshith-varshi/AccessProof |
| Branch | `claude/modest-bell-tazupa` (r19 `6014a18` + D-01..D-04 + release tooling) |
| Rehearsed commit | `e4bc14cad04bb82b876b8e312dd71fd948d7f46d` |
| Rehearsed artifact SHA-256 | `ac76072051c39434b846e019ea0a412a2f0e1f8b853edab06bf19fdc857b7b4b` (`git archive` + `RELEASE_COMMIT`) |
| Uncommitted changes | None in this checkout. The operator's local repository (`customer-rag-r13`, local commit `b0b3cd4`, possibly uncommitted SharePoint work) was **not inspected**; compare it before shipping |

Commits after `e4bc14c` change only `deploy/` and `docs/`. No file copied into
any image differs. `ship_via_ssm.sh` derives the release ID from the commit it ships.

## B. AWS deployment

Account `102076848988` (unverified) · eu-north-1 · `i-0c11427d4d9c1b438` ·
`/home/ubuntu/accessproof` · `docker-compose.ec2.yml` · release dir
`/home/ubuntu/accessproof-releases/r20-cert-presence-<commit12>/` (to be
created by the deploy script). **Nothing was executed on AWS.**

## C. Docker images

| | Previous (reported, not re-observed) | New |
|---|---|---|
| API | `accessproof/api:durable-gateway-history-r19-20261103` | `accessproof/api:r20-cert-presence-<commit12>` (built on EC2) |
| Web | `accessproof/web-v2:durable-gateway-history-r19-20261103` | `accessproof/web-v2:r20-cert-presence-<commit12>` |
| Worker | `accessproof/worker:verification-r11-20261101` | `accessproof/worker:r20-cert-presence-<commit12>` |

Local rehearsal image IDs (commit `e4bc14c`): api `3935ac358d23`, worker
`eec9ee1313df`, web `cab79c675405`. These are not pushed anywhere; EC2 builds its own.

## D. Database

Previous (reported): `p8c1e2f3a4b5`. Target: `r2b3c4d5e6f7`. Both migrations
are additive: they widen a column and create a table with forced RLS.
Backup: `pg_dump -Fc`, verified by `pg_restore --list`, runs before migrating.
Migration status in production: **not applied**.

## E. Test results (local; production categories BLOCKED)

| Category | Result |
|---|---|
| Backend unit | 670 passed, 0 failed |
| Integration | 160 passed, 0 failed, 4 skipped (Ollama ×3, live SharePoint fixture ×1) |
| Security | 472 passed, 0 failed |
| Contract / load | 10 / 1 passed |
| Ruff | changed files PASS; repo-wide 29 pre-existing findings in 2 files outside the release |
| Mypy (strict, changed modules) | PASS |
| Web | ESLint PASS, `tsc` PASS, `next build` PASS |
| Playwright | 59 passed, **2 failed**, 5 skipped. The failures are a pre-existing `/favicon.ico` 404 on the public page (desktop + mobile); `web-v2/public` is empty in r19 and r20 |
| PostgreSQL 17 migration | upgrade from `p8c1` PASS; RLS as non-superuser PASS (heartbeat 200, replay 409, cross-tenant 401, other tenant and no-context see 0 rows); downgrade → r19 `check_schema` PASS; re-upgrade PASS |
| Docker | api/worker/web builds PASS; API production-mode start + `/health/ready` PASS; worker start PASS; web `/login` 200 PASS |
| Deploy rehearsal (real script, stand-in host with r19 images at `p8c1` + seed data) | deploy PASS; manual rollback PASS; **automatic rollback after a failed post-migration health gate** PASS; no secrets in logs; db/redis never recreated |
| Production health, Guard, Gateway, RAG | **BLOCKED** |

## F. Production status

Not observed. Last reported by the operator: all services healthy.

## G. Core product status (unchanged by this work)

SharePoint source: connected, **not certified**, so SharePoint Protect stays
blocked by design. Guard, Gateway, Layer 1, Layer 2 and activation were not
observed live. Production Gateways predate the D-02 heartbeat and will report
`UNKNOWN` until customers re-install. `ACCESSPROOF_MICROSOFT_CERTIFIED_PROTECT_ENABLED=true`
does not certify any source.

## H. Rollback

Automatic in `deploy_on_ec2.sh`, manual via `rollback_on_ec2.sh`. Previous images
are never deleted. The downgrade is refused if Ed25519 certificates exist.
Rollback readiness: **rehearsed**.

## New findings during this task

* **D-05 (P1, infrastructure):** the app connects as the Postgres image's
  `POSTGRES_USER`, which is a SUPERUSER with BYPASSRLS. If production matches the
  repo's Compose file, every forced-RLS tenant policy is inert there. Tenant
  isolation would then rest on application-level `organization_id` filters
  (which are tested). The fix is an approved non-superuser application role.
* **Server Compose differs from the repo** (production reports Microsoft flags the
  repo Compose does not define), so the release changes only `.env` image lines.
* **The Compose `migrate` service builds from server source** and is not pinned to
  a release image. The deploy script migrates with the new API image instead.
* **Customer-hosted components:** D-03 (Guard) needs a Guard 0.1.5 package and
  customer reinstall. D-02 needs customers to re-run the new Gateway installer.
