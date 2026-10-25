# Gateway deployment runbook

Build locally with `docker compose --profile gateway build gateway`. Validate configuration using `docker compose --profile gateway config`. Populate customer-controlled `.env` values and deploy only after an authorized change review. Verify `/health/live`, `/health/ready`, Guard policy freshness, an allow challenge, a denial challenge, and a provenance failure before routing employee traffic.

Rollback removes Gateway routing first and returns the RAG to its documented pre-install state. Never leave a UI status claiming Protect after routing is removed.

## Controlled installer and rollback

The optional customer-run command is documented in `gateway-installation.md`.
It validates a declared supported Compose contract and stages a JSON override
without mutating the customer's original Compose file. `--apply` starts only
the Gateway (not the RAG service and not Protect).

The Gateway's `/health/live` endpoint is process liveness and is **not**
authorization readiness; `/health/ready` must be checked with an enrolled
Guard. A local Docker smoke test confirmed 200 on liveness and 503 on readiness
when Guard was unavailable.

If the **Gateway-only** installation fails, use the customer-approved
Compose project/service name to stop the Gateway service and investigate.
Do not run blanket `docker compose down` on the customer's application stack.

Routing must never be switched to a permissive direct-LLM fallback while the
AccessProof console claims that the application is protected. Before rollback,
disable the protected application via its authorized release procedures.

## Docker Compose deployment health contract

The customer-side package now checks `/health/ready` (not merely
`/health/live`) for Compose health. A Gateway process that cannot reach an
operational, policy-synchronized Guard must be reported **unhealthy**.
The shipped Gateway container uses a non-root user, a read-only filesystem,
no Linux capabilities, no-new-privileges, and bounded process/memory budgets.
These controls do not guarantee network isolation: customer firewall, Docker
network routing and application egress must also be reviewed.

## Emergency failed cutover behavior (current)

The approved reference cutover CLI and customer-cutover helper now stop
the selected RAG service if their post-cutover security tests fail. This
prevents silent restoration of an unprotected direct-model route. Operators
should verify service shutdown and use separately approved, fail-closed
recovery. Do not blindly run `docker compose up` on the original unprotected
RAG configuration while the user-facing application claims Protect.

### Loopback published port with internal RAG/model networks

For the Docker Compose reference workflow, put **only the Gateway** on a
separate non-internal `accessproof-gateway-host` bridge. The Gateway's port
remains bound to `127.0.0.1` on the customer host. Keep the RAG, Guard
and in-stack model on separately isolated internal networks. The Gateway
joins these internal networks to call Guard and model but the RAG must not
join either the model network or the host-access bridge. A model or Guard
added to the host bridge is an unsupported/certification-failing topology.

The sandbox test proved this arrangement lets the host reach
`/health/live`, while `/health/ready` still returns 503 if Guard is not
enrolled. The `customer_agent` refuses Gateway-only reference
certification if this Compose network boundary is broken.
