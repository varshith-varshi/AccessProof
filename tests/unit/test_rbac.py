from packages.domain.rbac import Permission, Role, allows


def test_auditor_is_read_only():
    assert allows(Role.AUDITOR, Permission.AUDIT_READ)
    assert not allows(Role.AUDITOR, Permission.TEST_RUN)


def test_owner_has_all_permissions():
    assert all(allows(Role.OWNER, p) for p in Permission)
