# AccessProof production deployment

AccessProof uses three public names:

| Purpose | URL |
| --- | --- |
| Marketing/landing site | `https://accessproof.in` |
| Application | `https://app.accessproof.in` |
| Control-plane API and runner endpoint | `https://api.accessproof.in` |

The browser uses same-origin `/api/*` and `/health/*` requests through the Next.js
application. This preserves host-only session and CSRF cookies on
`app.accessproof.in`. The web container sends those proxied requests to `api:8000`
on the private Docker network. Private runners use the public API URL, while each
customer RAG target retains its own configured URL and can remain private.

## DNS in GoDaddy

Create these records after the Oracle Cloud instance has a stable public IP:

| Type | Host | Value |
| --- | --- | --- |
| A | `@` | `<ORACLE_PUBLIC_IP>` |
| A | `app` | `<ORACLE_PUBLIC_IP>` |
| A | `api` | `<ORACLE_PUBLIC_IP>` |
| CNAME | `www` | `accessproof.in` |

Do not delete or replace existing email MX, SPF, DKIM, or DMARC records when adding
website DNS records.

## Environment

Copy `.env.production.example` to a private `.env.production`, replace every
placeholder, and do not commit it. `NEXT_PUBLIC_*` values are public build-time
configuration and must never contain credentials. `API_URL=http://api:8000` stays
inside Docker; `NEXT_PUBLIC_API_URL=https://api.accessproof.in` is the external
public API address.

Set `ACCESSPROOF_FORWARDED_ALLOW_IPS` to only the private address of the deployed
Nginx proxy. Do not set it to `*`: doing so would allow an arbitrary client to
forge `X-Forwarded-*` headers.

## OAuth/OIDC registration

For Microsoft Entra or another organization OIDC provider, register this exact
redirect URI:

```
https://app.accessproof.in/api/v1/auth/oidc/callback
```

This is routed by the app domain to the API and keeps browser session/CSRF cookies
host-only. Google Drive source authorization in the current product uses connector
credentials rather than a public browser callback; if a future Google OAuth browser
flow is added, register its explicit callback then rather than guessing one now.

## Deploy

Build/publish immutable API, worker, and web image tags, then on the server:

```bash
docker compose --env-file .env.production -f docker-compose.production.yml config -q
docker compose --env-file .env.production -f docker-compose.production.yml up -d
docker compose --env-file .env.production -f docker-compose.production.yml ps
```

Connect the Nginx container to the same private Docker network and install
`deploy/nginx/accessproof.conf`. The upstream names are the Compose service names
`web` and `api`. Create `/etc/nginx/snippets/accessproof-tls.conf` through Certbot
or your TLS provider; it must contain the certificate directives covering all four
hostnames. The root domain redirects to the app until a separate public landing site
is deployed. Only Nginx should publish ports 80 and 443. Keep PostgreSQL, Redis,
API port 8000, and Next.js port 3000 private.

## Checks before DNS cutover

1. Validate the rendered Compose file with `config -q`.
2. Confirm the API `/health/ready` endpoint through Nginx.
3. Confirm browser signup/login, email links, and one private-runner heartbeat.
4. Confirm the OIDC callback against a real Entra test tenant if OIDC is enabled.
5. Back up PostgreSQL and test a restore before accepting customer data.

Oracle Cloud firewall rules, DNS propagation, TLS certificates, production secrets,
SMTP credentials, and real Microsoft/Google tenant validation are external setup
steps and cannot be verified from this repository alone.
