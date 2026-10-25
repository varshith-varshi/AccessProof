# Synthetic performance and fault evidence — 2026-10-20

## Environment
User's Ubuntu laptop, isolated snapshot; local `PolicyCache` with SQLite, generated synthetic identities and documents; eight worker threads. No external Google Drive or enterprise RAG.

```text
BENCHMARK=local SQLite PolicyCache, 8 threads, synthetic principals
DECISIONS=2000 ALLOW=1000 DENY=1000
P50_MS=0.1281 P95_MS=0.3994 P99_MS=0.9038 MAX_MS=15.8797
THROUGHPUT_DECISIONS_PER_SEC=33228.8
SECURITY_OUTCOME=all 2000 synthetic decisions correct
```

These numbers measure only warmed local cache lookups. They are **not** Guard end-to-end latency, network costs, OAuth/Google Drive sync speed, multi-tenant concurrency, uptime or a production SLA.

## Failure injection exercised
- Guard 401/403/429/5xx; invalid JSON; failure at Layer 1, late-source validation and Layer 2.
- Buffered streaming model exception and unicode/size boundaries.
- Stale sync; unhealthy source; restart with old source health; policy rollover; source rebind; once-only context and JWT tenant mismatch.
- Full tests include local Postgres/Redis-oriented unit/integration mocks, but no live HA/load cluster or sustained soak.

**Pending:** measurable revocation source-to-deny timeline, p95/p99 of actual protected RAG latency, real Google provider outages, network partitions and hours-long recovery/soak.