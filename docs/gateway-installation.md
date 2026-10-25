# Gateway installation

Copy `packaging/gateway`, create `.env` from `.env.example`, bind the Gateway to an enrolled Guard, configure the model endpoint and its credentials, and provide the trusted ingestion public-key map. Start it with `docker compose up -d`. The package uses loopback binding by default. A reverse proxy may expose it only behind the customer's authenticated application boundary.

This package does not install Docker resources on a customer host automatically. That requires an authorized customer-side deployment agent and is therefore not claimed as one-click in this release.

## Local automated staging (new, controlled installer)

The optional local installer prepares the Gateway sidecar for an existing
Docker Compose deployment. **It does not modify the customer's application
source or turn on Protect.** The customer explicitly chooses whether to run
the generated deployment. The existing customer app must already expose a
configurable completion route and an independently attested retrieval manifest.

The customer's Compose service must truthfully implement and declare these
labels. Labels are a compatibility hint, NOT security proof:

```yaml
services:
  customer-rag:
    image: your-company/rag
    labels:
      com.accessproof.gateway.contract: accessproof.gateway/v1
      com.accessproof.gateway.enforces: attested-retrieval-and-buffered-output
      com.accessproof.gateway.route_env: ACCESSPROOF_CHAT_URL
```

Only add them to an application that actually supports the specified contract.
The Gateway is **not** a transparent universal OpenAI proxy.

Prepare a local JSON specification, kept outside source control:

```json
{
  "tenant_id": "your-registered-tenant-id",
  "application_id": "your-registered-rag-id",
  "rag_service": "customer-rag",
  "guard_url": "http://your-enrolled-guard:8080",
  "model_url": "https://your-model-provider/v1/chat/completions",
  "model_name": "configured-model",
  "model_token_env": "YOUR_MODEL_API_KEY",
  "trusted_public_keys": {
    "your-ingestion-key-id": "REPLACE_WITH_ACTUAL_ED25519_PUBLIC_KEY_BASE64URL"
  }
}
```

The keys in this example are placeholders and will fail validation until
replaced. Populate the model credential environment variable locally; do not
paste secrets into the specification or share them with AccessProof support.

Then on the **customer-authorized Docker host**:

```bash
python -m apps.gateway.accessproof_gateway.installer \
  --spec /secure/gateway-spec.json \
  --compose /customer/docker-compose.yml \
  --output /customer/accessproof-generated
```

This command creates restricted `gateway.env`, a Docker Compose JSON override,
and an installation record. Existing files are never overwritten. It does not
run Docker deployment changes.

With explicit approval, add `--apply` to **build and start only the Gateway**.
The application route remains unchanged. Docker Compose must support raw
`env_file` format. The generated Compose override contains the intended
routing changes for a later **certified** cutover only.

**DO NOT activate the RAG routing override or describe Protect as active**
until a customer-side challenge agent, complete provider authorization
verification and bypass/response release proof are available. These
certification features are not yet finished in the current codebase.

### Google Drive signed text ingestion

A customer-side source ingester can now fetch a `text/plain` document from
an approved Drive root and sign the exact verified revision. The customer
must provide an authorized Google OAuth access token and a **mode-0600 raw
32-byte Ed25519 private key file**, held exclusively by the ingestion service.

```bash
export ACCESSPROOF_GOOGLE_DRIVE_ACCESS_TOKEN="your-authorized-provider-token"
python -m connectors.google_drive.ingest_cli \
  --root-folder-id YOUR_APPROVED_DRIVE_ROOT \
  --file-id YOUR_TEXT_FILE_ID \
  --tenant-id YOUR_ACCESSPROOF_TENANT \
  --application-id YOUR_RAG_APP_ID \
  --source-id YOUR_REGISTERED_DRIVE_SOURCE_ID \
  --key-id customer-ingester-v1 \
  --private-key /secure/source-signing-key.raw \
  --output /secure/retrieved-documents.manifest.json
```

The output manifest is private (0600) and never overwrites existing files.
It can be passed to the supported Gateway route using the registered app ID
and authenticated employee question. This is a **one-shot source ingestion
utility**: it does not yet automate OAuth refresh, distributed vector-index
updates, or real-time production permission synchronization. Only signed
`text/plain` is supported by this path; native Docs and binary formats are
not currently covered.

No real customer Drive or identity tokens were used to verify this workflow.

### Installer success semantics and liveness verification

A successful `--apply` means only that the Gateway image built, the
customer-authorized Docker Compose service started, and
`http://127.0.0.1:<chosen-port>/health/live` returned status 200 within a
bounded startup window. The script refuses to replace a Gateway container
already present in the target Compose project. Failed new deployments
trigger Gateway-only rollback attempts; they never rewrite or stop the
customer's RAG application.

When the Guard has no valid installed policy, a deployed Gateway is
expected to return 503 from `/health/ready`. This is **not** proof of a
successful Protect installation. Never change customer traffic routing while
Guard readiness or customer-route certification is incomplete.

### Supported reference activation workflow (experimental)

After staging and starting the Gateway, follow the four-phase
machine/cutover/Guard-ack procedure in `docs/gateway-customer-validation.md`.
The frontend's Gateway setup panel reads the installer manifest and requests
a one-use nonce; it does not request Docker root permissions or ingest the
customer's model credentials. The customer-controlled machine agent
correlates Gateway HTTP response hashes with enrolled Guard audit records.

The reference cutover CLI requires `--approve-customer-rag-restart`,
restarts only the selected RAG service and sends synthetic employee-facing
requests. If certification fails, it attempts to STOP that RAG service,
rather than restoring an unprotected route. Operator-controlled recovery is
required. Any other production orchestration is unsupported.

**Reference network constraint:** The RAG service must already have a
dedicated internal network, the self-hosted model must be on a separate
internal network, and the Gateway must bridge the two. External hosted LLM
OpenAI-compatible third-party cloud endpoints still need independently
reviewed network egress controls and are not automatically certified.
The reference verifier now accepts **official Claude and Gemini HTTPS
endpoints** when only the Gateway has external egress and RAG remains on
a strictly internal bridge. Provider-live tests, identity/source checks,
network/firewall review and Guard challenges remain mandatory; passing
the Compose layout alone does not certify external APIs.
See `docs/gateway-native-llm-adapters.md`.

### Apply a reviewed staged Gateway without overwriting files

After inspecting the local stage files, use `--apply-staged` with the same
`--spec`, `--compose` and `--output` values. This path checks the exact
Compose + override digest, tenant/application binding, Gateway route, private
credentials and file modes; an existing Gateway still cannot be overwritten.
`--apply` should be used **instead of staging first** when starting with a
brand-new output directory. Neither option cuts over the customer RAG;
that requires the separate owner-authorized `customer_cutover` CLI after
the enrolled-machine reference challenges pass.
