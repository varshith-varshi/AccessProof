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

Never use a personal account or a production document that is not dedicated to the
test. AccessProof generates and cleans up its own marked synthetic resources inside the
configured boundary.
