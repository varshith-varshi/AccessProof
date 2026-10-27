# AccessProof model API adapter support — local implementation (2026-10-24)

## Implemented

The Gateway's security boundary remains:

1. Verify the caller's employee identity with Guard.
2. Verify signed source content and run Layer 1 (filter unauthorized chunks).
3. Build the **only** LLM input from allowed source bytes and untrusted
   employee-originated messages.
4. Call one configured LLM adapter **without forwarding the employee token**.
5. Fully buffer output, reject unsupported/tool/partial payloads, and
   run Layer 2 with signed source lineage.
6. Release only an approved text response or buffered SSE. Streaming model
   tokens, tool calls and multimodal output are not bypass routes.

Supported `ACCESSPROOF_GATEWAY_MODEL_PROVIDER` values:

| Value | Model API format | Endpoint | Auth |
|---|---|---|---|
| `openai-compatible` (default) | Chat Completions JSON, `choices[0].message.content` | Customer-owned model URL | Optional Bearer |
| `anthropic` | Claude native `POST /v1/messages` | `https://api.anthropic.com/v1/messages` | `x-api-key` and `anthropic-version: 2023-06-01` |
| `gemini` | Google native `:generateContent` | `https://generativelanguage.googleapis.com/v1beta/models/<MODEL_ID>:generateContent` | `x-goog-api-key` |

Model IDs must be chosen by the customer from their actual provider account.
The provider may require additional enrollment, billing, workspace scoping,
permissions, or region/data-processing review. A working API adapter does
not guarantee access to every provider model.

**No model change is required.** Existing compatible self-hosted LLMs still
use the default `openai-compatible` option. In all cases, the RAG must send
signed retrieval dependencies through the protected Gateway route; using a
compatible model API is not sufficient for protection.

## Docker operator install spec

Populate an existing mode-0600 `accessproof-install-spec.json` with the
matching values below (plus tenant, app, approved RAG service, Guard URL and
trusted ingestion public keys).

### Claude native

```json
{
  "model_provider": "anthropic",
  "model_url": "https://api.anthropic.com/v1/messages",
  "model_name": "CUSTOMER_SELECTED_CLAUDE_MODEL_ID",
  "model_token_env": "ANTHROPIC_CUSTOMER_KEY"
}
```

### Gemini native

```json
{
  "model_provider": "gemini",
  "model_url": "https://generativelanguage.googleapis.com/v1beta/models/CUSTOMER_SELECTED_GEMINI_MODEL_ID:generateContent",
  "model_name": "CUSTOMER_SELECTED_GEMINI_MODEL_ID",
  "model_token_env": "GEMINI_CUSTOMER_KEY"
}
```

Set the named credential in the shell environment *on the customer host*
before running the approved installer. The installer copies it to a private
mode-0600 Gateway `env_file` and does not put it in a Docker command
argument, printed receipt, the browser or Git. Protect installation
still requires customer approval and challenge/cutover certification.

For direct Compose development configuration, use:
`ACCESSPROOF_GATEWAY_MODEL_PROVIDER`,
`ACCESSPROOF_GATEWAY_MODEL_URL`,
`ACCESSPROOF_GATEWAY_MODEL_NAME`,
`ACCESSPROOF_GATEWAY_MODEL_BEARER_TOKEN` (the field name is backward
compatible; its contents become the relevant provider-specific API key).

### Custom non-compatible proprietary LLM APIs

A company-specific integration can install a trusted Python adapter
implementing `ModelAdapter`:

- `validate(model_url, model_name, api_key)`
- `request(messages, model_name) -> JSON body`
- `headers(api_key) -> HTTP headers`
- `extract_text(json_payload) -> completed string`

Explicit local invocation uses
`GatewaySettings(model_provider="custom", ...)` and
`create_app(settings, model_adapter=CustomerApprovedAdapter())`.
A real customer must package, review and maintain the adapter with their
Gateway code. There is **no** dynamic module import, unreviewed plugin
download or automatic API guessing. Standard installer `InstallationSpec`
still rejects `custom` unless a separately reviewed deployment package
supports that adapter. This preserves fail-closed behavior for unknown APIs.

## Gateway upstream transport and readiness safety

The Gateway now validates both the Guard service URL and the model service
URL before startup. **Plaintext HTTP is accepted only for explicitly
private-network destinations** (IPv4 RFC1918, loopback, IPv6 ULA, or an
isolated single-label Docker service name). Public IP addresses, dotted
DNS names, and other off-network destinations must use HTTPS. Link-local
metadata services, wildcard bind addresses and special-use IPs are not
permitted even with HTTPS. This prevents accidental cleartext transmission
of verified employee identity or protected document context.

A single-label Docker name remains permitted only because the approved
reference deployment independently verifies that the RAG cannot reach
the model without crossing the Gateway. Network isolation, customer ingress
TLS, and a no-bypass cutover challenge are **separate mandatory release
checks**. Arbitrary custom DNS suffixes (even `.internal`) do not grant an
automatic HTTP exception; configure HTTPS or a reviewed private service name.

The Gateway `GET /health/ready` endpoint now checks the Guard for the
**configured application ID**. A healthy Guard bound to another app, a Shadow
application or a stale permission source is not a ready Gateway. Liveness
(`/health/live`) is only process health; neither endpoint alone is a
certification or a substitute for independent customer-route testing.

## Network isolation and release constraints

The supported Docker reference static network checker now permits official
native provider HTTPS *only* when RAG is on strictly internal networks,
the Gateway alone has a separate public-host bridge, and Guard is in the
reviewed Compose network. The RAG has no direct public model route.
The provider URL/credential are pinned and redirects are disabled.

This static test does not certify network ACLs outside Compose, host or
router compromise, DNS/firewall changes, customer proxies, secret management,
provider residency/retention terms, live Anthropic/Gemini API behavior,
sustained traffic, or billing/rate-limit handling. The existing enrolled
Guard challenge, employee-facing route cutover and source/revocation tests
must still pass before real production Protect can be claimed.

**Known scope:** Text-only completed responses. Tools, intermediate model
thoughts, direct model streaming and multimodal output remain out of scope;
the Gateway blocks rather than relays unsupported output.
