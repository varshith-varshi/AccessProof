# AccessProof native and custom LLM adapters: implementation report
Date: 2026-10-24
Repository: /home/white-devil/Downloads/accessproof/f15

## Product result
AccessProof is no longer limited to the OpenAI Chat Completions wire format
inside its *customer-side buffered Gateway*.

**Implemented and locally tested**:
- Existing OpenAI-compatible model protocol, unchanged default.
- Anthropic Claude native Messages API adapter with official HTTPS endpoint,
  required model ID, x-api-key and version header.
- Google Gemini native GenerateContent API adapter with official HTTPS endpoint,
  model-ID URL matching, and x-goog-api-key header.
- Explicit adapter Protocol for proprietary company-hosted model APIs: a trusted
  customer-specific Python implementation can be installed and supplied to
  create_app; unrecognized formats remain fail-closed.
- Per-provider selection from GatewaySettings/from_env, Docker Compose and
  customer-side immutable installation spec; credentials passed via customer-
  host mode-0600 environment file, never customer browser or CLI arguments.
- web-v2 /integrations/setup model provider selector and sample config.
- Official native cloud-provider static Docker reference network support:
  protected RAG on internal bridge, Gateway alone on outbound host bridge;
  untrusted/unknown cloud URLs and direct RAG egress layouts still rejected.

## Security contract preserved
Every provider is called only by the same trusted GatewayService.generate
callback, itself invoked exclusively by ProtectedRAG.run after Layer 1.
Signed source bytes become untrusted model user text; source-authored content
never becomes a system/developer message. The employee bearer token is
never forwarded upstream. Provider responses are fully bounded/buffered,
parsed through strict text-only completion rules, and sent through Layer 2
before either JSON or buffered SSE response output. Tool use, partial
generations, malformed frames and opaque multimodal data fail closed.
No native model integration bypasses Guard or source revocation checks.

## Files introduced/updated
- apps/gateway/accessproof_gateway/model_adapters.py (new)
- apps/gateway/accessproof_gateway/app.py
- apps/gateway/accessproof_gateway/installer.py
- apps/gateway/accessproof_gateway/customer_agent.py
- apps/gateway/accessproof_gateway/network_boundary.py
- apps/gateway/accessproof_gateway/integration_wizard.py
- docker-compose.yml, .env.example
- web-v2/app/integrations/setup/page.tsx
- docs/gateway-native-llm-adapters.md (configuration, limitations)
- docs/gateway-compatibility-matrix.md
- docs/gateway-installation.md
- tests/unit/test_gateway_model_providers.py (new)
- tests/unit/test_gateway_network_boundary.py (additional regressions)

## Evidence and limitations
- Provider request/response and Guard-negative adversarial tests use a local
  httpx MockTransport, not paid production model API credentials.
- Customer-authored arbitrary custom APIs require a separately packaged,
  reviewed adapter and deployment support; standard Docker installer accepts
  the explicitly supported native/compatible protocols only.
- Native cloud provider static network isolation is exercised on actual
  Docker Compose normalized configuration for both Claude and Gemini.
  Docker Compose normalizes internal:false away; code and tests now accept
  the secure default while rejecting internal:true and direct customer RAG
  egress.
- The reference customer-side one-click flow still requires signed retrieval
  evidence, enrolled Guard challenge, real employee-facing cutover, source
  revocation certification and explicit human approval before Protect.
- SharePoint effective permission certification is unrelated and remains
  a separate release gate; no change to that boundary.
- Live provider API behavior, customer billing/access, firewall routing,
  DNS, source permission semantics and load/HA/recovery are NOT production-
  certified by the tests performed here.
- No real Microsoft/Google/Anthropic customer credentials were supplied,
  no production service deployment was performed, and unrelated worktree
  changes were preserved.

## Test files
Backend complete-suite log:
  /tmp/accessproof_native_llm_full_suite_20261024.log
Focused Gateway + security suite:
  /tmp/ap_native_llm_gateway_focused_final.log
Native provider and network tests:
  /tmp/ap_native_compose_normalized_tests.log
Frontend lint, types and production build:
  /tmp/ap_native_web_lint.log
  /tmp/ap_native_web_typecheck.log
  /tmp/ap_native_web_build.log

Exact full test counts must be read from the completed execution log.

## Final locally observed test results
- Full Python backend test suite: **794 passed, 1 expected failure, 0
  unexpected failures**, exit code 0. The expected failure is the
  preexisting known metadata-only provenance integrity gap.
- Focused Gateway + customer installer + real TCP Guard + universal cache
  security regression: **168 passed**, exit code 0.
- Native provider/cloud reference validation after Compose-normalization fix:
  both Claude and Gemini real Docker Compose fixture stage/config checks
  passed, with no source Compose mutation.
- Targeted cloud/network and provider tests after final fix: **50 passed**.
- web-v2: ESLint, TypeScript and production build passed, including
  /integrations/setup and the provider selector.
- Python Ruff, compileall and Docker Compose config passed.

The full-suite execution began before the final Docker Compose normalized
network fix; the affected provider/network/cutover modules were independently
rerun after that fix in the focused regression tests.
