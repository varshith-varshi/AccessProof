"""Compatibility re-export: the remote route certificate logic lives in
``packages.crypto.remote_route_certificate`` so the production API image (which
does not ship ``apps/gateway``) can verify and enforce certificates."""
from packages.crypto.remote_route_certificate import *  # noqa: F401,F403
from packages.crypto.remote_route_certificate import (  # noqa: F401
    ATTESTATION_MAX_AGE, ATTESTATION_SCHEMA, BINDING_FIELDS, MAX_AGE, REQUIRED_CHECKS, SCHEMA, RouteCertificationError,
    _b64, _canonical, evaluate, fingerprint, issue, issue_attestation, make_binding, verify_certificate, verify_signed,
)
