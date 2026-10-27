# Microsoft 365 trial validation status — 27 October 2026

AccessProof SharePoint Protect: **NOT CERTIFIED**.

## Verified live behavior

A Microsoft 365 test-tenant account was authenticated through the connected Microsoft SharePoint service. Read-only Graph calls to list drives and resolve the tenant SharePoint site both returned HTTP 400 with the provider message: `Tenant does not have a SPO license.`

This may indicate missing license assignment, a disabled SharePoint service plan, unfinished tenant provisioning, or a Microsoft Graph backend issue. It is **not** sufficient evidence that the trial was not purchased or that SharePoint is unavailable in Business Basic.

No live Microsoft document, permission or employee revocation test succeeded. No licenses were purchased or changed. No tenant files were uploaded, deleted or shared.

## Unblock path

In the Microsoft 365 admin center, inspect Billing > Your products for an active Business Basic trial. Under Users > Active users, verify that the intended test account has a trial license assigned and that SharePoint Online is enabled. Confirm the SharePoint admin center and a test site work in the browser. If they do while Graph still returns the licensing error, contact Microsoft support with the request ID.

After SharePoint Graph works, set up an isolated site and approved test folder; create Alice (allowed) and Bob (negative control); use the local synthetic fixtures in `customer_simulation/microsoft365_live_trial_fixtures`. Bob must also pass a separate allowed-document control, so an invalid or unlicensed token is not mistaken for document-specific access denial.

## Read-only preflight tool

`scripts/validate_microsoft_trial_preflight.py` accepts only operator environment configuration and does no write or permission mutation. By default it checks configuration without network traffic. With `--live`, and only when configured, it acquires an app-only Graph token, validates the SharePoint site/library/folder boundary, and reads a bounded source inventory. Passing this check does **not** activate Protect.

The AccessProof application registration, live delegated Alice/Bob permissions, LLM/RAG path, cache-hit denial, and signed source-specific Protect evidence are still unverified.
