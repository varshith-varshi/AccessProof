# AccessProof: discover many, select exactly ONE chatbot

## Requested product scope

A customer may host multiple existing chatbots on one computer. AccessProof
discovers supported running Docker Compose RAG services but the customer
chooses only ONE chatbot for this onboarding. The other applications must
remain unchanged. This release does not add multi-chatbot protection,
multiple simultaneous Gateway installations or a new host-enrollment backend.

## Customer behavior

1. Connect an approved SharePoint source and register one AccessProof
   application in the existing dashboard. Download the private pairing file.
2. Download and run the customer Gateway installer on the authorized Docker
   host: `python3 ~/Downloads/accessproof-gateway-connector.zip`.
3. If several supported RAG services are detected, the CLI displays a
   numbered selection list. Choose ONE. If stdin is noninteractive, use
   `--discover` and then `--select DISCOVERED_ID` with the pairing file.
   A single supported RAG is selected without needing a numbered menu.
4. The chosen running Compose service is checked against fresh Docker inspect
   metadata, not identified merely by its display name. Only a supported
   source integration contract is eligible.
5. The existing single-Gateway installation and pairing workflow then runs
   for the chosen Compose service. It retains the current
   `accessproof-gateway` service name and port 8090, rather than installing
   an independent Gateway for each detected service.
6. A matching existing Gateway is handled by the legacy adoption path. A
   mismatched or ambiguous installation fails closed, rather than being
   silently rebound to another chatbot.
7. Installation is NOT production Protect certification. Source, Guard,
   Layer 1/2 evidence and approved cutover requirements are unchanged.

## Safety constraints

- `--plan --select ONE_ID` creates exactly one read-only preview;
  `--plan --select A --select B` is rejected.
- `--select` in a real installation requires the existing pairing
  credentials and the normal operator-approved install process.
- A service's Docker Compose project/service identity and container ID are
  rechecked at the time of selection.
- When Docker reports multiple Compose files for the selected running
  service, automatic one-file inference fails closed. The customer must
  review the Compose setup and use `--compose` where suitable. This is a
  deliberate limitation rather than silently deploying against the wrong
  merged Compose configuration.
- If several supported services exist within the SAME Compose file, the
  installer cannot silently fall back to a service named `rag`; explicit
  `--rag-service` or a selected discovered application is required.
- The standard loopback Gateway port 8090 must be available. It is a
  planning check, not a durable reservation or deployment attestation.
- The CLI never receives arbitrary remote commands from the SaaS control
  plane and discovery does not expose the Docker socket or customer secrets.

## Verification

- Unit suite: 656 passed during scope correction; final focused
  selection/discovery/ZIP regression tests: 42 passed.
- Relevant existing integration tests: 2 passed.
- Ruff and mypy checks passed.
- A rebuilt ZIP was executed directly on the authorized Ubuntu host.
  Docker returned 14 inventory records, two SUPPORTED RAGs.
  Exactly one was planned and selecting both returned an error.
- Customer ZIP SHA-256:
  `eef1db90c4a414a64d4eb5f70f77a8956544868ea82b60bc23c614912db66791`.
- No live Docker or production AWS deployment mutations occurred.
- Customer web dashboard is unchanged in this release; selection is the
  local installer CLI, not a new cloud-side discovery UI.
- All independent source and customer Gateway security certification remains
  pending and is not implied by this user-experience correction.

## Existing product vs. this enhancement

Previous multi-Gateway installation helper APIs remain in source for
backward compatibility and test coverage, but the newly exposed customer
discovery/selection entrypoint now limits the onboarding to ONE chatbot.
This release does not automatically protect a customer RAG without its
supported signed retrieval, identity and output gate integration.
