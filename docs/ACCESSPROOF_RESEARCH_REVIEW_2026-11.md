# Research review and core-pipeline upgrades — November 2026

**Method and limits.** Literature located with web search. `arxiv.org` is blocked by
this engineering environment's network policy, so full texts could not be read.
Findings below rely on the abstracts and search summaries of each paper. Where a
claim could not be verified against the full text it is marked *(unverified)*.

## What the literature says, and how AccessProof measures up

| # | Research finding | Before | Action |
|---|---|---|---|
| 1 | **Participant-aware access control.** In shared contexts a document may inform a response only if **every** active participant may read it. Probabilistic defenses (prompt sanitization, output filtering, isolation) are insufficient; enforcement must be deterministic. — Microsoft Research, *Enterprise AI Must Enforce Participant-Aware Access Control*, arXiv:2509.14608 | Gateway authorized only the requesting employee | **Implemented (R-1)** |
| 2 | **Cross-prompt injection (XPIA) exfiltration.** Injected instructions in retrieved content make the model emit markdown images or links that carry data; chat clients fetch them with no click. Prompt-level defenses alone are insufficient. — same paper; Hines et al., *Spotlighting*, arXiv:2403.14720 | Layer 2 verified provenance but released output verbatim | **Implemented (R-2)** deterministic output filter |
| 3 | **Spotlighting.** Mark untrusted input so the model can separate it from instructions; attackers who learn fixed delimiters can bypass them. — arXiv:2403.14720 | Fixed `[source=…]` framing | **Implemented (R-3)** per-request nonce boundaries and defusing of forged markers |
| 4 | **Permission-aware RAG over multiple resources** needs fine-grained, per-source IAM filtering. — Park et al., *Permission-Aware RAG*, IEEE Access | Already enforced: per-source bindings, chunk-level narrowing, multi-source Guard v2 | No change |
| 5 | **Cross-document inference.** Pre-retrieval identity checks alone may not prevent inference across documents. — *Towards Secure RAG: A Comprehensive Review*, arXiv:2603.21654 | Layer 1 per chunk + Layer 2 trace completeness; aggregation of individually authorized data is permitted by design | Documented residual risk |
| 6 | **Semantic/KV cache timing side channels** reveal other users' prompts. — Pang et al., *The Early Bird Catches the Leak*, arXiv:2409.20002 | Cached answers re-authorized per employee and revision; timing side channels out of scope | Documented; recommend per-tenant cache partitioning |
| 7 | **Membership inference against RAG** (document existence via answers). — arXiv:2405.20446; *Riddle Me This!*, arXiv:2502.00306 (CCS 2025) | Denied-only retrieval returns a distinct 403 to the RAG app | Documented residual: the customer RAG should map denials to its normal "no results" reply |
| 8 | **Knowledge poisoning** (PoisonedRAG, arXiv:2402.07867) | Attestation proves origin and integrity, not truthfulness | Out of authorization scope; documented |
| 9 | LLM-based RBAC filtering (ARBITER, arXiv:2512.20535; ~85% accuracy) | AccessProof uses deterministic provider ACLs | Not adopted: a probabilistic filter must not make authorization decisions |

## Upgrades shipped in this change

### R-1 Participant-aware authorization (`packages/rag_core/participants.py`)
`POST /v1/chat/completions` (also snapshot chat and cached-answer authorize)
accepts `participant_tokens`: verified identity tokens of the other people who will
see the answer. `ParticipantAwareGuard`:
* runs each participant's own Layer 1 and returns the **exact intersection**. A
  whole-document grant never widens another participant's chunk-level grant;
* binds each participant's Layer 2 to that participant's own Layer 1 decision;
* releases only if every participant allows at one identical authorization revision;
* fails closed on any unverifiable participant, mode mismatch or revision drift.

Supplying participants can only narrow access. Requests without them behave as before.
Tests: `tests/security/test_participant_aware_authorization.py`, run against the real
Guard and Gateway (Alice/Bob/Carol matrix).

### R-2 Output exfiltration guard (`packages/rag_core/output_safety.py`)
After Layer 2 allows, every URL in a markdown image or link, autolink, bare URL,
reference definition or `data:`/`javascript:` scheme whose host is not on
`ACCESSPROOF_GATEWAY_OUTPUT_ALLOWED_HOSTS` is neutralized. Active HTML (`img`,
`iframe`, `script`, …) is removed. Lookalike hosts and credentials-in-URL are rejected.
The response reports `output_links_removed`. Streaming releases the same sanitized text.
Tests: `tests/security/test_output_exfiltration_guard.py` (13 payloads plus
allowlist, false-positive and configuration tests) and an end-to-end Gateway case.

**Operator note:** set the allowlist to the company's own hosts (for example
`contoso.sharepoint.com,.docs.contoso.com`) so citation links survive.

### R-3 Spotlighting delimiters (Gateway context construction)
Each source is fenced by `<<<SOURCE {nonce} …>>> … <<<END SOURCE {nonce}>>>` with
a fresh 64-bit nonce per request. The system prompt names the nonce. Lines in
untrusted text that imitate framing are prefixed with an invisible separator.
Context stays in a user-role message (never system), on every model adapter.

## Not implemented (recommended next)
* **Uniform denial responses** to blunt membership inference (customer RAG integration).
* **Participant tokens in the customer installer and route challenge** (the shared-chat bot path).
* **Datamarking/encoding spotlighting variants**: need answer-quality evaluation with the customer's model.

## Sources
- [Enterprise AI Must Enforce Participant-Aware Access Control (arXiv:2509.14608)](https://arxiv.org/abs/2509.14608) · [Microsoft Research page](https://www.microsoft.com/en-us/research/publication/enterprise-ai-must-enforce-participant-aware-access-control/)
- [Defending Against Indirect Prompt Injection Attacks With Spotlighting (arXiv:2403.14720)](https://arxiv.org/pdf/2403.14720)
- [Permission-Aware RAG: IAM-Based Access Filtering in Multi-Resource Environments](https://snu.elsevierpure.com/en/publications/permission-aware-rag-identity-and-access-management-iam-based-acc/)
- [Towards Secure Retrieval-Augmented Generation: A Comprehensive Review (arXiv:2603.21654)](https://arxiv.org/pdf/2603.21654)
- [ARBITER: AI-Driven Filtering for Role-Based Access Control (arXiv:2512.20535)](https://arxiv.org/pdf/2512.20535)
- [The Early Bird Catches the Leak: Timing Side Channels in LLM Serving Systems (arXiv:2409.20002)](https://arxiv.org/html/2409.20002v5)
- [Is My Data in Your Retrieval Database? MIA against RAG (arXiv:2405.20446)](https://arxiv.org/pdf/2405.20446)
- [Riddle Me This! Stealthy Membership Inference for RAG (arXiv:2502.00306)](https://arxiv.org/abs/2502.00306)
- [PoisonedRAG: Knowledge Corruption Attacks to RAG (arXiv:2402.07867)](https://arxiv.org/pdf/2402.07867)
- [FACTS About Building RAG-based Chatbots (arXiv:2407.07858)](https://arxiv.org/pdf/2407.07858)
