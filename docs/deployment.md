# Deployment

## Development infrastructure

```bash
./scripts/dev.sh infra
alembic upgrade head
uvicorn apps.api.accessproof_api.app:app --reload --port 8000
cd apps/web && npm install && npm run dev
```

## Full Docker profile

```bash
docker compose --profile full up --build
```

Services are PostgreSQL 17, Redis 7, FastAPI control plane, durable webhook worker and Next.js web. The private runner is a separate optional profile because it requires a real runner identity.

## Production runtime

Production uses managed PostgreSQL and Redis plus an external TLS reverse proxy. The
runtime Compose file publishes no ports, so only the proxy should be internet-facing.
For the `accessproof.in` domain plan, DNS, Nginx, OAuth redirects, and Oracle Cloud
cutover steps, read [production-deployment.md](production-deployment.md).

```bash
cp .env.production.example .env.production
# Edit every REPLACE value and use immutable image digests or release tags.
docker compose --env-file .env.production -f docker-compose.production.yml config -q
docker compose --env-file .env.production -f docker-compose.production.yml up -d
```

The proxy must terminate TLS for `WEB_ORIGIN`, forward the original Host header to
the web container, and proxy `/api/*` and `/health/*` through the web service. Do
not expose PostgreSQL, Redis, or the API to the public network. Configure
`ACCESSPROOF_FORWARDED_ALLOW_IPS` with only the proxy's private address before
enabling forwarded headers.

At startup the API rejects production configuration that uses SQLite, development or
short secrets, an unencrypted web origin, console email, wildcard hosts, or the RLS
bypass. Configure backups, restore drills, image scanning, ingress/egress policy,
and a proper secrets manager/KMS in the deployment platform.
