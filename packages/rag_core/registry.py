"""Static, reviewable registry of adapters shipped by this repository.

The control plane exposes this metadata for discovery only. It never imports or
executes customer adapter code.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from .contract import ADAPTER_CONTRACT_VERSION


@dataclass(frozen=True)
class AdapterRegistration:
    id: str
    name: str
    category: str
    status: str
    language: str
    contract_version: str
    pre_generation_filtering: bool
    output_verification: bool
    shadow_mode: bool
    protect_mode: bool
    installation: str
    limitation: str
    adapter_version: str
    framework: str
    framework_versions: tuple[str, ...]
    required_guard_version: str
    required_configuration: tuple[str, ...]
    deployment_models: tuple[str, ...]
    validation_requirements: tuple[str, ...]
    certification: str


# Production V1 has exactly one customer integration surface. The other
# historical framework adapters are retired from registration and discovery;
# security primitives formerly shared with them remain internal to Gateway.
_REGISTRY: tuple[AdapterRegistration, ...] = (
    AdapterRegistration(
        id="accessproof-gateway",
        name="AccessProof Gateway",
        category="Customer-side enforcement Gateway",
        status="AVAILABLE",
        language="HTTPS / Docker",
        contract_version=ADAPTER_CONTRACT_VERSION,
        pre_generation_filtering=True,
        output_verification=True,
        shadow_mode=False,
        protect_mode=True,
        installation="Deploy Gateway and Guard beside a reviewed Docker RAG application; forward trusted, attested retrieval manifests through the customer-side Gateway.",
        limitation="Only the explicitly challenged attested-manifest Gateway route is eligible. Opaque RAG, direct model calls, unsupported cache and tool paths cannot be certified.",
        adapter_version="0.1.0",
        framework="Attested retrieval HTTP Gateway",
        framework_versions=("Buffered HTTP", "SSE after full response verification"),
        required_guard_version=">=0.1.0",
        required_configuration=("Gateway URL", "Guard URL", "application ID", "tenant ID", "trusted ingestion public key", "verified employee bearer token"),
        deployment_models=("reviewed customer-side Docker Compose", "private VPC"),
        validation_requirements=("attested allowed request", "revoked-document denial", "content-forgery rejection", "verified Layer 2 release", "authorized employee-facing route cutover"),
        certification="REFERENCE_IMPLEMENTATION_TESTED",
    ),
)


def adapter_registry() -> list[dict[str, object]]:
    return [asdict(item) for item in _REGISTRY]
