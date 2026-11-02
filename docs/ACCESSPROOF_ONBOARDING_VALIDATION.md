# Onboarding validation (2026-11-02)

## Customer rehearsal (mission §7) — NOT PERFORMED

The account `saivarshith2406@gmail.com` / workspace `sai`, the website, the
Guard/Gateway downloads and the customer test host were not reachable from this
environment. No stage was executed, and no database rows were inserted to
simulate one.

| Stage | Status |
|---|---|
| 1 Sign in / verify identity | BLOCKED (network) |
| 2 Connect SharePoint | BLOCKED |
| 3 Guard download + install | BLOCKED |
| 4 Gateway download + install | BLOCKED |
| 5 Real RAG questions | BLOCKED |
| 6–8 Fix / activate / independent check | BLOCKED |

## Local journey coverage (PASS)

`test_customer_lifecycle_over_http.py` (source → Guard → RAG → revoke over
HTTP), `test_guard_onboarding.py`, `test_gateway_dashboard_selection.py`,
`test_single_chatbot_choice.py`, and `test_gateway_presence.py` (claim →
credential → heartbeat → activation gate).

## What changed for customers

After installing, the installer now writes `gateway-presence.env`, recreates
only the Gateway service, and the dashboard shows **Gateway live connection:
Connected · ready / Connected · not ready / Disconnected / Unknown**, based
on authenticated heartbeats. No manual RAG test worksheet was added.

## Onboarding reset (O-04) — proposed design, not implemented

`POST /api/v1/organization/onboarding-reset` (OWNER only, MFA-fresh):

1. `GET …/onboarding-reset/preview` returns the exact rows in scope (AI
   applications, Gateway installations, pairing keys, verification runs,
   source connections, Guard registrations) plus a scope digest.
2. The owner confirms with that digest within 10 minutes.
3. The reset revokes machine credentials and deletes only the previewed
   onboarding rows. It preserves users, password hashes, MFA, memberships,
   the organization and **all audit history**, and writes an audit event.

It was not built here because it is destructive and could not be validated
against production data.
