# Automated RAG integration

AccessProof supports one local reference pattern: a configured RAG retrieval service sends an attested retrieval manifest to the customer-side Gateway, which then calls an OpenAI-compatible non-streaming model. This is configuration-driven only where the existing RAG can already emit the documented manifest. It is not universal automatic interception of arbitrary RAG memory, tools, or vector stores.

The Gateway route accepts `application_id`, `employee_question`, optional employee-authored conversation turns, and signed retrieved resources. It rejects generic `messages`, system/developer roles, tool outputs, cache context, and streaming.

## Current secure local installation and validation components

- `apps.gateway.accessproof_gateway.installer` is an owner-run Docker
  configuration/staging tool, not a SaaS-side remote host executor. It checks
  that the existing RAG service declares the supported attested-manifest
  contract, writes mode-0600 configuration and starts **only Gateway** after
  explicit `--apply`. It never silently turns on Protect.
- `connectors.google_drive.ingest_cli` fetches source content using the
  customer's authorized Google Drive OAuth token and signs exact source
  versions under a mode-0600 customer-side Ed25519 private key. It is a
  one-shot text/plain ingestion component, not an automatic vector-indexer.
- `apps.gateway.accessproof_gateway.challenge_agent.GatewayRouteChallenge`
  now reads the *actual loopback HTTP response bytes* from a configured
  Gateway and tests allow, deny, forged content, Layer 2 revocation and
  Guard readiness. Its output explicitly states
  `production_certification: false`. These checks cannot prove that an
  arbitrary customer RAG has no uninstrumented routes.
- The control-plane preflight remains fail closed until an **enrolled,
  replay-resistant, machine-attested customer-side challenge and release
  protocol** proves the complete RAG path. No browser checkbox or local
  diagnostic evidence alone is accepted as a production certificate.
