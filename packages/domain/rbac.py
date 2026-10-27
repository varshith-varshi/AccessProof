from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    OWNER = "OWNER"
    ADMIN = "ADMIN"
    ENGINEER = "ENGINEER"
    VIEWER = "VIEWER"
    AUDITOR = "AUDITOR"


class Permission(str, Enum):
    ORG_ADMIN = "org.admin"
    BILLING_MANAGE = "billing.manage"
    MEMBER_MANAGE = "member.manage"
    PROJECT_WRITE = "project.write"
    PROJECT_DELETE = "project.delete"
    ORG_DELETE = "org.delete"
    RETENTION_MANAGE = "retention.manage"
    SOURCE_WRITE = "source.write"
    TARGET_WRITE = "target.write"
    RUNNER_WRITE = "runner.write"
    TEST_WRITE = "test.write"
    TEST_RUN = "test.run"
    RESULT_READ = "result.read"
    REPORT_READ = "report.read"
    AUDIT_READ = "audit.read"
    SECRET_MANAGE = "secret.manage"
    CI_MANAGE = "ci.manage"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.OWNER: frozenset(Permission),
    Role.ADMIN: frozenset(
        {
            Permission.ORG_ADMIN,
            Permission.MEMBER_MANAGE,
            Permission.PROJECT_WRITE,
            Permission.PROJECT_DELETE,
            Permission.RETENTION_MANAGE,
            Permission.SOURCE_WRITE,
            Permission.TARGET_WRITE,
            Permission.RUNNER_WRITE,
            Permission.TEST_WRITE,
            Permission.TEST_RUN,
            Permission.RESULT_READ,
            Permission.REPORT_READ,
            Permission.AUDIT_READ,
            Permission.SECRET_MANAGE,
            Permission.CI_MANAGE,
        }
    ),
    Role.ENGINEER: frozenset(
        {
            Permission.PROJECT_WRITE,
            Permission.SOURCE_WRITE,
            Permission.TARGET_WRITE,
            Permission.TEST_WRITE,
            Permission.TEST_RUN,
            Permission.RESULT_READ,
            Permission.REPORT_READ,
            Permission.CI_MANAGE,
        }
    ),
    Role.VIEWER: frozenset({Permission.RESULT_READ, Permission.REPORT_READ}),
    Role.AUDITOR: frozenset(
        {Permission.RESULT_READ, Permission.REPORT_READ, Permission.AUDIT_READ}
    ),
}


def allows(role: Role, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS[role]
