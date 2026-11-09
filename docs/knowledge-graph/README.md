# AccessProof knowledge graph — AI navigation index

**Purpose:** Give coding agents and engineers a machine-readable map of the current AccessProof codebase: *what exists, how it connects, the end-to-end security paths, where to read code, and what is still conditional*. This is a repository navigation aid, **not** proof that a customer is protected or that live AWS has a particular state.

## Start here (Codex / Claude / other assistants)

1. Read root [AGENTS.md](../../AGENTS.md); Claude Code should also read [CLAUDE.md](../../CLAUDE.md).
2. Load [graph.json](graph.json) (canonical structured representation); inspect `nodes`, `edges`, `workflows`, `scopes`, and `guardrails`.
3. Start from the node relevant to your task, follow its `source_paths`, then trace incoming and outgoing `edges`.
4. **Re-read actual source and tests.** The graph is indexed as of **2026-11-09**; changes may have occurred since.
5. If editing graph topology, run the commands below and update the corresponding source paths.

| File | Purpose |
| --- | --- |
| [graph.json](graph.json) | Structured graph: 45 source-linked nodes, 79 typed directed edges, four workflows, provenance boundaries, maturity scopes. |
| [architecture.mmd](architecture.mmd) | Generated Mermaid overview (a focused subgraph, not the full edge set). |
| [../../scripts/validate_knowledge_graph.py](../../scripts/validate_knowledge_graph.py) | Offline graph and repository-path validator, plus deterministic Mermaid generator. |
| [../../tests/unit/test_knowledge_graph.py](../../tests/unit/test_knowledge_graph.py) | Validator regression tests. |

## How to follow the real product

**1. Permission/source lane:** Microsoft 365 admin consent **and** selected SharePoint site grant → Microsoft Graph selected-scope adapter → ACL/directory sync → stable Entra employee identity resolution → source/tenant-bound policy revision → Guard policy installation. A live provider grant and fresh sync are **not interchangeable** with a synthetic fixture.

**2. Customer RAG lane:** customer-owned private Linux Docker Compose RAG → host-local discovery (candidate, not certification) → customer-approved installer → single selected RAG/Gateway pairing → complete covered response route. Customer RAGs need signed resource/chunk provenance and trusted identity; AccessProof does not silently intercept arbitrary apps.

**3. Enforced request lane:** retrieved resources + signed provenance + employee identity → Gateway and Guard **Layer 1** resource check → only authorized chunks enter LLM context → complete response is buffered → Gateway and Guard **Layer 2** recheck current authorization/provenance → release or withhold answer; audit each decision. Native incremental streaming, WebSockets, arbitrary agents/tools, unknown caches and alternate output paths are not automatically certified.

**4. Protection and certification lane:** explicit authorized `Enable Protection` with mandatory source/Guard/Gateway readiness. The separate typed Owner Approval phrase was **removed** by commit `4beeff5`. `PROTECTED_MANUAL_VALIDATION_PENDING` means protection active while independent route validation is pending; `PROTECTED_VERIFIED` needs fresh backend evidence. Manual Alice/Bob or customer employee testing remains a separate useful validation step. Never infer either status from pairing or a heartbeat alone.

**5. Operations lane:** source/route certificates have finite validity; revocations and expiry matter. An isolated AWS certificate **status watcher** was deployed, but its live signing/renewal is **not laptop-independent** and candidate KMS signer trust is not cut over. See [independent rollout status](../INDEPENDENT_CERTIFIER_AWS_ROLLOUT_2026-11-08.md).

## Maturity and source-of-truth rules

- `implemented` ≠ live-provider-certified. `pilot` means our **SharePoint + Entra guided-pilot** customer scope. `conditional` means customer-specific integration/security proof is needed. `operational_limited` means deployed work has explicit caveats.
- Current customer-safe claims are tracked in [customer claims register](../CUSTOMER_CLAIMS_REGISTER_2026-11-07.md) and [launch audit](../CUSTOMER_LAUNCH_AUDIT_2026-11-07.md).
- Root `README.md` and `ACCESSPROOF_CONTEXT.md` contain **older Google Drive-first snapshots**; their commercial scope and Owner-approval instructions must not override newer code and dated release evidence. Similarly, sections of [Nov 5 customer onboarding notes](../CUSTOMER_ONBOARDING_CURRENT_2026-11-05.md) precede removal of the typed Owner Approval.
- Source code and current tests > graph summaries. Verified **live production behavior and certificate state** > all checked-in documents. If sources conflict, record the conflict instead of silently choosing a convenient interpretation.
- This graph deliberately does **not** include customer credentials, token contents, AWS account numbers, private evidence, proprietary document text, or production secrets.

## Query and validate

```bash
# Validate all nodes, source links, edge references, workflow steps, and diagram freshness.
python3 scripts/validate_knowledge_graph.py

# Regenerate the Mermaid view after editing graph.json.
python3 scripts/validate_knowledge_graph.py --write-diagram

# Example: read the Gateway node and all edges connected to it.
python3 - <<'PY'
import json
g = json.load(open("docs/knowledge-graph/graph.json"))
print(next(n for n in g["nodes"] if n["id"] == "gateway"))
print(*[e for e in g["edges"] if "gateway" in (e["from"], e["to"])], sep="\\n")
PY
```

### Maintenance discipline

Update the graph when a component's code path, boundary, certification condition or customer-facing scope changes. Keep **stable node IDs**, link to **existing repo-relative paths**, and use typed edges. Regenerate Mermaid using the validator; do not hand-edit the generated file. The validator catches broken paths and dangling references, **not** stale claims or missing real-world proof. It intentionally never connects to AWS, Graph, the database, or production.
