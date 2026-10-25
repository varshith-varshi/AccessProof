# AccessProof V4 — Integration Compatibility

**Snapshot:** 2026-10-24
**Status:** reference tooling only. A scan or adapter label is **never** a
certification of a customer application.

## 1. What the compatibility scanner is

`scripts/compatibility_scan.py` is a read-only static scan of a customer RAG
source tree. It identifies integration evidence and blockers so a human can
scope a live integration. It does not import, execute, or call target code.

```bash
# JSON report (default)
.venv/bin/python scripts/compatibility_scan.py /path/to/customer-rag

# Human-readable blockers only
.venv/bin/python scripts/compatibility_scan.py /path/to/customer-rag --format text

# Prometheus exposition of bypass-finding counts
.venv/bin/python scripts/compatibility_scan.py /path/to/customer-rag --format prometheus
```

Every JSON report contains:

| Field | Meaning |
|---|---|
| `schema` | `accessproof.compatibility_scan/v1` |
| `scanner.read_only` | Always `true` |
| `scanner.executed_target_code` | Always `false` |
| `scanner.followed_symlinks` | Always `false` |
| `certification_status` | Always `NOT_CERTIFIED` |
| `bypass_findings` | Detected paths that can bypass a protected RAG release |
| `certification_blockers` | Reasons human review must not treat the app as ready |
| `artifacts_examined` | Relative `file` references only; never source lines |

### Detectable evidence

- Identity/JWT/OIDC patterns and whether the same artifact references an
  AccessProof boundary.
- AI-related HTTP routes and whether AccessProof is referenced.
- Vector retrieval constructs and whether an authorization predicate
  (`allowed_resource_ids`, `document_id = ANY`, tenant/resource filter) is
  visible.
- Model clients (OpenAI, Anthropic, Gemini) and direct provider endpoints.
- Cache usage and whether current-authorization rechecks are referenced.
- Tool/agent, WebSocket, background-worker and streaming constructs.

### Deliberate limits and safety properties

- Python/TypeScript/JavaScript text files only (`.py`, `.ts`, `.tsx`, `.js`,
  `.jsx`, `.mjs`, `.cjs`).
- `.env*`, keys, certificates, credential files, symlinks, dependency
  directories, and test directories are skipped.
- Files larger than the byte bound (default 512 KiB) are counted but not read.
- Regex detection can produce false positives and false negatives.
- A clean scan does **not** mean `SUPPORTED`; an authenticated route challenge
  and Guard audit evidence are still required. See
  [20_ROUTE_CERTIFICATION_AND_REVOCATION_EVIDENCE.md](20_ROUTE_CERTIFICATION_AND_REVOCATION_EVIDENCE.md).

Reproduction: `tests/unit/test_compatibility_scanner.py` covers protected
routes, cache reauthorization, direct model/streaming/WebSocket/tool findings,
secret/symlink exclusion, and the guarantee that target code is never executed.

## 2. Route support envelopes

The canonical capability registry (`packages/capability_registry.py`, exported
to [03_FEATURE_AND_CAPABILITY_MATRIX.csv](03_FEATURE_AND_CAPABILITY_MATRIX.csv))
records these route states:

| Route class | State | Evidence | Constraint |
|---|---|---|---|
| Buffered HTTP RAG response through the reference Gateway | `SUPPORTED` | `LOCAL_INTEGRATION_VERIFIED` | Layer 2 must complete before release. |
| Buffered SSE through the reference Gateway | `PARTIAL` | `LOCAL_INTEGRATION_VERIFIED` | Tokens must be buffered; native incremental release is not protected. |
| Native streaming | `UNSUPPORTED` | none | No certification path. |
| WebSocket | `UNSUPPORTED` | none | No certification path. |
| Tools / agents / side effects | `UNSUPPORTED` | none | Separate action authorization is required. |
| Background worker results | `UNSUPPORTED` | none | Can bypass the synchronous release gate. |
| Cache hits | `PARTIAL` | `LOCAL_INTEGRATION_VERIFIED` | Must be reauthorized for the current employee and revision. |

An adapter registration (`accessproof-gateway`, `generic-python`,
`langchain-python`, etc.) indicates an implemented contract, not a customer
deployment certification. `generic-http` and Microsoft 365 are not
Protect-eligible in the registry.

## 3. Interpretation rules

1. A `SUPPORTED` registry entry is not `LIVE_PROVIDER_VERIFIED`; no live
   provider or customer tenant was used for this build.
2. An `UNSUPPORTED` path must be removed from the protected response path or
   explicitly excluded from the customer's protection claim.
3. A certificate for the reference Gateway route does not cover arbitrary
   application endpoints, caches, workers, tools, or alternate model calls.
4. Do not present scanner output, adapter status, or `mode=protect` as a
   security certification.
