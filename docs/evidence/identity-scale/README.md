# Automatic identity resolution: scale evidence (2026-11-03)

Harness: `scripts/bench/identity_scale.py`. It runs the real
`synchronize_directory`, reconciliation, the Guard envelope query and the
Guard cache against a disposable local PostgreSQL 17 (`postgres:17-alpine`),
with Microsoft Graph mocked. Synthetic identities only: 2% guests (never
bound) and 1% disabled in the lifecycle step. Laptop: x86_64, Ubuntu 24.04.

| Identities | Initial sync | SELECTs | Unchanged re-sync | 1% disabled | identity_version p50 | Envelope raw (gzip) | Guard install | Guard resolve p50/p95/p99 | Concurrent reconcile |
|---|---|---|---|---|---|---|---|---|---|
| 100 | 0.04 s | 8 | 0.01 s | 0.02 s | 0.9 ms | 29 KB | 0.001 s | 2.6/3.4/40 µs | 0 duplicates |
| 1,000 | 0.27 s | 8 | 0.09 s | 0.11 s | 1.1 ms | 292 KB | 0.004 s | 2.8/3.1/4.4 µs | 0 duplicates |
| 10,000 | 2.4 s | 8 | 0.8 s | 1.0 s | 4.8 ms | 2.9 MB (57 KB) | 0.03 s | 3.6/5.6/7.8 µs | 0 duplicates |
| 100,000 | 27.4 s | 8 | 9.8 s | 11.2 s | 34 ms | 29 MB (576 KB) | 0.49 s | 6.2/8.7/10.6 µs | 0 duplicates |

## Reading the table
* **No N+1.** The SELECT count is constant at 8 whatever the directory size.
  Before, it was one query per user, group and membership. Lifecycle changes
  cost work proportional to the number of *changed* principals.
* **Unchanged re-sync writes no bindings.** The 3 writes are the sync cursor.
* **Delivery.** The full set is sent only when it changed, plus a forced
  refresh at least every 300 s. It is gzip-compressed on the Guard policy
  route (52×).
* **Concurrency.** Two workers reconciled the same source at once. One hit
  the unique constraint (IntegrityError, rolled back) and the other
  completed: no duplicates, and no retry needed.
* **Onboarding effort is constant.** No per-employee administrator action at
  any size.

## Limits (not hidden)
* **Memory.** Peak RSS of the benchmark process was about 1.6 GB at 100,000.
  ORM objects for every principal and binding are materialised, plus the
  harness's own envelope copy. The production worker host (t3.small, 2 GB)
  is therefore **validated up to about 10,000 directory users** (273 MB peak).
  100,000 needs a larger worker, or a future streaming/batched reconciliation.
* `identity_version` is computed on every Guard poll: 34 ms of aggregate
  database work at 100,000. Acceptable for a few Guards; cache it for many.
* Real Microsoft Graph pagination and throttling were not exercised. Graph
  is mocked here, and the adapter's existing bounded pagination and retry
  apply.
