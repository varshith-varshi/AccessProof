# Customer onboarding

1. Create a project for a dedicated non-production test boundary.
2. Connect the source boundary and explicitly authorize synthetic-resource mutation.
3. Add two dedicated test identities: an allowed user and a denied control user.
4. Configure the RAG endpoint and forward the selected identity through its supported
   authentication header or session mechanism.
5. Create an enrollment code and install the private runner in the network that can
   reach both the source and RAG endpoint.
6. Confirm the runner is **online**, validate the source and identities, and run one
   positive-control test before relying on revocation measurements.
7. Run the revocation suite and review the persisted T0/T1/T2 timeline, evidence, and
   final PASS/FAIL/INCONCLUSIVE outcome.
8. Create a Guard in **Guards**, download and extract the customer package, and
   launch `start.ps1` (Windows), `start.command` (macOS), or `start.sh` (Linux).
   The launcher starts the container and opens a local setup page. Paste the
   one-time token and enter the RAG token's trusted OIDC issuer and audience.
   No command-line enrollment or machine-credential copying is required.
9. Register the customer AI application in **AI applications**, select the adapter
   matching its retrieval layer, bind the Guard and source, and keep the application
   in Shadow mode while validating the integration.
10. Add the adapter at the point between retrieval and generation. Pass the
   authenticated employee token from the customer's request context, preserve the
   source/resource identifiers on every result, and buffer the complete model
   response until Layer 2 approves its trusted provenance.
11. Complete the Layer 1, Layer 2, provenance, and buffering checks in the
    application readiness view. Enable Protect only after all checks pass.

The adapter contract and concrete Python examples are documented in
[`docs/rag-adapter-contract.md`](rag-adapter-contract.md). A framework without a
trusted retrieval hook or a response buffering boundary needs a customer-specific
adapter; do not claim it is protected based on prompt instructions or generated
citations alone.

Never use a personal account or a production document that is not dedicated to the
test. AccessProof generates and cleans up its own marked synthetic resources inside the
configured boundary.
