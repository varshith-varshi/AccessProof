# Event-driven authorization readiness

Verdict: **READY_FOR_LOCAL_DEMO**, not production certified.

Local evidence covers a synthetic Drive watch registration response, secure
callback validation and deduplication, durable event-to-worker handoff,
authoritative ACL-sync invocation, authenticated Guard wake-up, rollback-safe
existing policy installation, and fresh-database migration.

Not yet validated against a live Google Workspace tenant: `changes.watch`
subscription lifecycle/renewal, callback delivery, directory-user events,
group membership audit coverage, shared-drive effective permission semantics,
provider throttling, and measured provider-revocation-to-denial latency.
Existing periodic ACL/directory reconciliation remains mandatory for recovery.
