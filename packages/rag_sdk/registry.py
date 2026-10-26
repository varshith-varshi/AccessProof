"""Static, reviewable registry of adapters shipped by this repository.

The control plane exposes this metadata for discovery only. It never imports or
executes customer adapter code.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from .adapters import ADAPTER_CONTRACT_VERSION


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


_REGISTRY: tuple[AdapterRegistration, ...] = (
    AdapterRegistration(
        id="accessproof-gateway", name="AccessProof RAG Security Gateway", category="Customer-side gateway", status="AVAILABLE",
        language="HTTP / Python", contract_version=ADAPTER_CONTRACT_VERSION,
        pre_generation_filtering=True, output_verification=True, shadow_mode=False, protect_mode=True,
        installation="Deploy the customer-side Gateway and send its attested retrieval manifest to /v1/chat/completions.",
        limitation="It protects only the documented attested retrieval-manifest route; an opaque RAG or generic model proxy is not automatically protected.",
        adapter_version="0.1.0", framework="OpenAI-compatible model API", framework_versions=("non-streaming chat completions",), required_guard_version=">=0.1.0",
        required_configuration=("Gateway URL", "Guard URL", "application ID", "tenant ID", "trusted ingestion public key", "verified employee bearer token"),
        deployment_models=("customer-side container", "private VPC", "reverse proxy"),
        validation_requirements=("attested allow request", "revoked-resource denial", "provenance failure", "zero-byte pre-Layer-2 release"), certification="REFERENCE_IMPLEMENTATION_TESTED",
    ),
    AdapterRegistration(
        id="generic-python", name="Generic Python RAG", category="RAG framework", status="AVAILABLE",
        language="Python", contract_version=ADAPTER_CONTRACT_VERSION,
        pre_generation_filtering=True, output_verification=True, shadow_mode=True, protect_mode=True,
        installation="Use packages.rag_sdk.RAGAdapter", limitation="Requires stable source/resource metadata and a response buffering boundary.",
        adapter_version="0.1.0", framework="Framework-neutral Python", framework_versions=(">=3.11",), required_guard_version=">=0.1.0",
        required_configuration=("Guard URL", "application ID", "permission source ID", "verified employee bearer token"),
        deployment_models=("library", "sidecar Guard", "private VPC"), validation_requirements=("Layer 1 synthetic denial", "Layer 2 provenance escape", "Guard fail-closed"), certification="IMPLEMENTED_AND_TESTED",
    ),
    AdapterRegistration(
        id="generic-typescript", name="Custom TypeScript / Node.js RAG", category="RAG framework", status="AVAILABLE",
        language="TypeScript", contract_version=ADAPTER_CONTRACT_VERSION,
        pre_generation_filtering=True, output_verification=True, shadow_mode=True, protect_mode=True,
        installation="Use @accessproof/rag-sdk GuardClient, ProtectedRAG, and RAGAdapter at the retrieval-to-generation boundary.",
        limitation="Responses must remain buffered until Layer 2 completes; the package is currently distributed privately and is not published to npm.",
        adapter_version="0.1.0", framework="Framework-neutral Node.js", framework_versions=("Node.js >=20", "TypeScript >=5"), required_guard_version=">=0.1.0",
        required_configuration=("Guard URL", "application ID", "permission source ID", "verified employee bearer token"),
        deployment_models=("library", "sidecar Guard", "private VPC"), validation_requirements=("Layer 1 synthetic denial", "Layer 2 provenance escape", "Guard fail-closed"), certification="IMPLEMENTED_AND_TESTED",
    ),
    AdapterRegistration(
        id="langchain-python", name="LangChain Python", category="RAG framework", status="BETA",
        language="Python", contract_version=ADAPTER_CONTRACT_VERSION,
        pre_generation_filtering=True, output_verification=True, shadow_mode=True, protect_mode=True,
        installation="Wrap retrieved LangChain Documents with packages.rag_sdk.LangChainAdapter before prompt construction.", limitation="The application must pass the authenticated employee token; validate metadata mapping against the deployed LangChain version.",
        adapter_version="0.1.0", framework="LangChain", framework_versions=("Python integration contract",), required_guard_version=">=0.1.0",
        required_configuration=("metadata source_id", "metadata resource_id", "verified employee bearer token"), deployment_models=("library", "sidecar Guard"),
        validation_requirements=("Real LangChain invocation in customer build", "metadata mapping diagnostic", "revocation test"), certification="IMPLEMENTED_NOT_FRAMEWORK_CERTIFIED",
    ),
    AdapterRegistration(
        id="llamaindex-python", name="LlamaIndex Python", category="RAG framework", status="BETA",
        language="Python", contract_version=ADAPTER_CONTRACT_VERSION,
        pre_generation_filtering=True, output_verification=True, shadow_mode=True, protect_mode=True,
        installation="Filter retrieved LlamaIndex nodes with packages.rag_sdk.LlamaIndexAdapter before synthesis.", limitation="The node metadata must contain an authoritative resource id; validate against the deployed LlamaIndex version.",
        adapter_version="0.1.0", framework="LlamaIndex", framework_versions=("Python integration contract",), required_guard_version=">=0.1.0",
        required_configuration=("node source_id", "node resource_id", "verified employee bearer token"), deployment_models=("library", "sidecar Guard"),
        validation_requirements=("Real LlamaIndex invocation in customer build", "node provenance diagnostic", "revocation test"), certification="IMPLEMENTED_NOT_FRAMEWORK_CERTIFIED",
    ),
    AdapterRegistration(
        id="langchain-typescript", name="LangChain TypeScript", category="RAG framework", status="BETA",
        language="TypeScript", contract_version=ADAPTER_CONTRACT_VERSION,
        pre_generation_filtering=True, output_verification=True, shadow_mode=True, protect_mode=True,
        installation="Wrap retrieved LangChain documents with @accessproof/rag-sdk LangChainAdapter before prompt construction.",
        limitation="The structural adapter is tested against the contract, but no real LangChain JS release is pinned or certified in this repository.",
        adapter_version="0.1.0", framework="LangChain JS", framework_versions=("Customer validation required",), required_guard_version=">=0.1.0",
        required_configuration=("metadata source_id", "metadata resource_id", "verified employee bearer token"), deployment_models=("library", "sidecar Guard"),
        validation_requirements=("Real LangChain JS invocation in customer build", "metadata mapping diagnostic", "revocation test"), certification="IMPLEMENTED_NOT_FRAMEWORK_CERTIFIED",
    ),
    AdapterRegistration(
        id="haystack-python", name="Haystack Python", category="RAG framework", status="BETA",
        language="Python", contract_version=ADAPTER_CONTRACT_VERSION,
        pre_generation_filtering=True, output_verification=True, shadow_mode=True, protect_mode=True,
        installation="Filter retrieved Haystack Documents with packages.rag_sdk.HaystackAdapter before generation.", limitation="Validate the document metadata mapping against the deployed Haystack version.",
        adapter_version="0.1.0", framework="Haystack", framework_versions=("Python integration contract",), required_guard_version=">=0.1.0",
        required_configuration=("document source_id", "document resource_id", "verified employee bearer token"), deployment_models=("library", "sidecar Guard"),
        validation_requirements=("Real Haystack invocation in customer build", "metadata diagnostic", "revocation test"), certification="IMPLEMENTED_NOT_FRAMEWORK_CERTIFIED",
    ),
    AdapterRegistration(
        id="generic-http", name="Generic HTTP target", category="Connectivity", status="PARTIAL",
        language="Any", contract_version="target-config/v1",
        pre_generation_filtering=False, output_verification=False, shadow_mode=True, protect_mode=False,
        installation="Configure an HTTP target for testing, or call the versioned Guard API at the retrieval boundary for enforcement.", limitation="Connectivity and evidence parsing alone do not provide Layer 1 enforcement inside a customer RAG.",
        adapter_version="0.1.0", framework="Custom HTTP", framework_versions=("HTTP/1.1", "HTTP/2"), required_guard_version=">=0.1.0",
        required_configuration=("internal Guard URL", "application ID", "trusted resource metadata", "verified bearer token"), deployment_models=("sidecar", "internal service", "private VPC"),
        validation_requirements=("Retrieval-boundary proof", "provenance-boundary proof", "failure-mode test"), certification="CONNECTIVITY_ONLY",
    ),
)


def adapter_registry() -> list[dict[str, object]]:
    return [asdict(item) for item in _REGISTRY]
