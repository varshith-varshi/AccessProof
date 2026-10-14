from types import SimpleNamespace

from apps.api.accessproof_api import db as db_module


class _Connection:
    dialect = SimpleNamespace(name="postgresql")

    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    def execute(self, statement, params=None):
        self.calls.append((str(statement), params or {}))


def test_rls_context_is_reapplied_on_every_transaction():
    assert db_module.settings.rls_bypass is False
    session = SimpleNamespace(info={"accessproof.organization_id": "org-a"})
    connection = _Connection()

    db_module._apply_rls_context(session, None, connection)

    assert len(connection.calls) == 2
    assert "accessproof.rls_bypass" in connection.calls[0][0]
    assert connection.calls[0][1]["value"] == "off"
    assert "accessproof.organization_id" in connection.calls[1][0]
    assert connection.calls[1][1]["org_id"] == "org-a"


def test_rls_worker_bypass_does_not_require_tenant():
    assert db_module.settings.rls_bypass is False
    session = SimpleNamespace(info={"accessproof.rls_bypass": True})
    connection = _Connection()

    db_module._apply_rls_context(session, None, connection)

    assert len(connection.calls) == 1
    assert connection.calls[0][1]["value"] == "on"
