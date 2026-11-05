# Reusable customer onboarding smoke (R44)

Run on the authorized repository checkout, without using real tenants:

```bash
scripts/smoke_customer_onboarding.sh \
  "$HOME/.ap-id/release-cache/accessproof-gateway-connector-v6.zip" \
  bab5f15f62c5186235677e489d7020654e72600d1f999a83554fa160a5dd91d9
```

This checks the exact published ZIP bytes, the embedded runtime's manifest digest, the updated challenge CLI source, and isolated API-level regressions for Guard enrollment, Gateway presence/heartbeat, route challenge, installer failure reporting, and synthetic RAG → real local Guard HTTP request/response authorization including streaming and denial. These add local TCP service tests but not a fresh real Docker customer installation. It needs Python dependencies but **does not need AWS access, real employee credentials or Docker**, and doesn't mutate production. It is repeatable after every installer build. Do not reuse an old checksum for a newly built ZIP.

**Evidence boundary:** Green `ONBOARDING_SMOKE_PASS` is an offline artifact/integration-regression result, not fresh external customer installation, authenticated cloud pairing, SharePoint consent, route certification, or human Owner approval. The earlier R43 fresh production pilot paired successfully, but R44 must still be tried on a separately authorized Linux Docker test host before claiming full fresh-install coverage for R44.

**Fresh host manual acceptance:** use the authenticated dashboard to download the live ZIP, compare its SHA-256 to this release's pinned digest, enroll a new isolated Guard, and use a distinct synthetic RAG/organization to run the customer installer. Require a live `CONNECTED` heartbeat and unchanged `pilot-hr-rag` protection. Stop before source/route certification or Owner approval unless the relevant authorized humans participate. Archive/revoke synthetic resources after collecting sanitized evidence. Never reuse a real customer's Microsoft password, employee token or signing key in synthetic tests.
