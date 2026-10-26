# AccessProof web-v2

`web-v2` is the isolated replacement web experience for AccessProof. It uses the existing FastAPI control plane and does not modify or import the legacy `apps/web` application.

## Local development

Requirements: Node.js 22 and an AccessProof API listening on port 8000.

```bash
cd web-v2
cp .env.example .env.local
npm ci
npm run dev
```

Open `http://localhost:3001`. Browser requests use the same-origin `/api` proxy, which forwards to the server-only `ACCESSPROOF_API_URL`.

## Configuration

| Variable | Purpose | Example |
| --- | --- | --- |
| `ACCESSPROOF_API_URL` | Server-side destination for the API proxy | `http://localhost:8000` |
| `NEXT_PUBLIC_SITE_URL` | Canonical public web origin | `http://localhost:3001` |
| `NEXT_PUBLIC_ENVIRONMENT` | Visible deployment environment label | `development` |

These values must not contain credentials. Authentication remains in secure HTTP-only cookies issued by the existing API.

## Validation

```bash
npm run lint
npm run typecheck
npm run build
npm run test:e2e
npm audit --omit=dev
```

The browser suite covers public pages, session routing, authenticated dashboard rendering, Guard enrollment, and mobile navigation. Its API responses are deterministic fixtures; hosted integration must additionally run against a real AccessProof API.

## Container

```bash
docker build -t accessproof-web-v2 .
docker run --rm -p 3001:3000 \
  -e ACCESSPROOF_API_URL=http://host.docker.internal:8000 \
  -e NEXT_PUBLIC_SITE_URL=http://localhost:3001 \
  accessproof-web-v2
```

The runtime uses an unprivileged user and exposes a health check on `/`.

## Product boundaries

The current API supports dashboard, source, target, permission-event, Guard, and audit views. Employee/effective-access inventory, browser-readable protection decisions, control-plane reports, and full application binding/readiness APIs are not yet available. The corresponding pages state that limitation and do not fabricate data.

See [CUTOVER.md](./CUTOVER.md) for the deployment sequence and rollback plan.
