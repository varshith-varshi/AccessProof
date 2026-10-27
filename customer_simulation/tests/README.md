# Digital twin test map

`tests/integration/test_customer_lifecycle_over_http.py` exercises real control-plane, Guard, SDK, revocation, stale-source, audit and loopback TCP boundaries. `tests/integration/test_synthetic_customer_http_boundary.py` exercises the customer RAG demo over TCP. Connector, OAuth, identity, tenant, and adversarial regressions reside in the repository's established `tests/` suites and are referenced by the scenario matrix.
