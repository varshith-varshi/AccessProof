"""Framework adapters for integrating customer RAG pipelines with Guard.

The adapters deliberately normalize retrieval results into the small, stable
AccessProof contract before calling :class:`ProtectedRAG`.  They do not try to
identify a user from a document, prompt, or model output.  The caller must
provide the employee access token and the Guard remains responsible for
cryptographic identity verification and authorization.

Only metadata supplied by the application is used for resource identity.  A
resource id is never derived from content or generated locally because doing
so would make revocation and provenance non-deterministic.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from .protection import ProtectedRAG, ProtectedResponse, RetrievedResource

ADAPTER_CONTRACT_VERSION = "accessproof.rag/v1"
_T = TypeVar("_T")


class AdapterConfigurationError(ValueError):
    """Raised when a retrieval result cannot carry trusted stable metadata."""


@dataclass(frozen=True)
class AdapterCapabilities:
    """Capabilities advertised by an adapter to an integration registry."""

    name: str
    contract_version: str = ADAPTER_CONTRACT_VERSION
    layer1_filtering: bool = True
    layer2_provenance: bool = True
    buffered_release: bool = True
    streaming_release: bool = False


GENERIC_CAPABILITIES = AdapterCapabilities(name="generic-python")
LANGCHAIN_CAPABILITIES = AdapterCapabilities(name="langchain")
LLAMAINDEX_CAPABILITIES = AdapterCapabilities(name="llamaindex")
HAYSTACK_CAPABILITIES = AdapterCapabilities(name="haystack")


def _metadata(document: Any) -> Mapping[str, Any]:
    value = getattr(document, "metadata", None)
    if isinstance(value, Mapping):
        return value
    # LlamaIndex nodes commonly expose metadata on ``node``.
    node = getattr(document, "node", None)
    value = getattr(node, "metadata", None)
    if isinstance(value, Mapping):
        return value
    if isinstance(document, Mapping):
        value = document.get("metadata")
        if isinstance(value, Mapping):
            return value
    return {}


def _value(document: Any, key: str) -> Any:
    if isinstance(document, Mapping):
        return document.get(key)
    return getattr(document, key, None)


def _content(document: Any) -> str:
    for key in ("page_content", "text", "content"):
        value = _value(document, key)
        if isinstance(value, str):
            return value
    getter = getattr(document, "get_content", None)
    if callable(getter):
        value = getter()
        if isinstance(value, str):
            return value
    node = getattr(document, "node", None)
    getter = getattr(node, "get_content", None)
    if callable(getter):
        value = getter()
        if isinstance(value, str):
            return value
    return ""


def _first_string(values: Iterable[Any]) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _consistent_identifier(
    metadata: Mapping[str, Any], keys: tuple[str, ...], label: str,
) -> str | None:
    """Reject ambiguous provider-origin metadata instead of choosing an alias.

    In particular, a framework document must not claim an allowed resource
    through one metadata key while identifying a different resource through
    another. Choosing the first key silently launders the second source into
    the registered Guard authorization scope.
    """
    values: list[str] = []
    for key in dict.fromkeys(keys):
        raw = metadata.get(key)
        if raw is None or raw == "":
            continue
        if not isinstance(raw, str) or not raw.strip():
            raise AdapterConfigurationError(f"Invalid {label} metadata in {key}")
        values.append(raw.strip())
    if len(set(values)) > 1:
        raise AdapterConfigurationError(f"Conflicting {label} metadata")
    return values[0] if values else None


def normalize_document(
    document: Any,
    *,
    source_id: str | None = None,
    resource_id_key: str = "resource_id",
    chunk_id_key: str = "chunk_id",
) -> RetrievedResource:
    """Convert one framework document into an AccessProof resource.

    ``resource_id_key`` and ``chunk_id_key`` are explicit application-owned
    metadata keys.  A few common aliases are accepted for interoperability,
    but content, vector indexes, and array positions are never used as ids.
    """
    metadata = _metadata(document)
    declared_source = _consistent_identifier(
        metadata, ("accessproof_source_id", "source_id"), "source identity",
    )
    configured_source = _first_string((source_id,))
    if configured_source and declared_source and configured_source != declared_source:
        raise AdapterConfigurationError(
            "Retrieved document source does not match the registered AccessProof source"
        )
    resolved_source = configured_source or declared_source
    resolved_resource = _consistent_identifier(
        metadata,
        (resource_id_key, "accessproof_resource_id", "source_resource_id", "document_id", "file_id"),
        "resource identity",
    )
    if not resolved_source:
        raise AdapterConfigurationError(
            "Each retrieved document requires source_id or accessproof_source_id metadata"
        )
    if not resolved_resource:
        raise AdapterConfigurationError(
            "Each retrieved document requires stable resource_id metadata; content cannot be used"
        )
    resolved_chunk = _consistent_identifier(
        metadata,
        (chunk_id_key, "accessproof_chunk_id", "chunk_id", "node_id"),
        "chunk identity",
    )
    return RetrievedResource(
        source_id=resolved_source,
        resource_id=resolved_resource,
        chunk_id=resolved_chunk,
        content=_content(document),
        content_version=_consistent_identifier(
            metadata, ("accessproof_content_version", "content_version"), "content version",
        ),
        content_attestation=_consistent_identifier(
            metadata, ("accessproof_content_attestation", "content_attestation"),
            "content attestation",
        ),
    )


def normalize_documents(
    documents: Iterable[Any],
    *,
    source_id: str | None = None,
    resource_id_key: str = "resource_id",
    chunk_id_key: str = "chunk_id",
) -> list[RetrievedResource]:
    """Normalize a complete retriever result while preserving result order."""
    return [
        normalize_document(
            document,
            source_id=source_id,
            resource_id_key=resource_id_key,
            chunk_id_key=chunk_id_key,
        )
        for document in documents
    ]


class RAGAdapter(Generic[_T]):
    """Drop-in adapter for a Python retriever and generator.

    ``generate`` receives the original customer document objects that survived
    Layer 1.  Layer 2 is checked before the returned text is released.  This
    makes the adapter usable with LangChain, LlamaIndex, Haystack, or a custom
    retriever without importing any of those optional frameworks.
    """

    capabilities = GENERIC_CAPABILITIES

    def __init__(
        self,
        protected_rag: ProtectedRAG,
        *,
        source_id: str | None = None,
        resource_id_key: str = "resource_id",
        chunk_id_key: str = "chunk_id",
    ) -> None:
        self.protected_rag = protected_rag
        self.source_id = source_id
        self.resource_id_key = resource_id_key
        self.chunk_id_key = chunk_id_key

    @staticmethod
    def _resource_key(resource: RetrievedResource) -> tuple[str, str, str | None]:
        return resource.source_id, resource.resource_id, resource.chunk_id

    def run(
        self,
        *,
        employee_token: str,
        application_id: str,
        documents: Sequence[_T],
        generate: Callable[[list[_T]], str | Iterable[str]],
        request_id: str | None = None,
        regenerate: Callable[[list[_T]], str | Iterable[str]] | None = None,
        source_trace: Callable[[], list[RetrievedResource]] | None = None,
    ) -> ProtectedResponse:
        # Framework/vector-store Document objects are commonly mutable and
        # shared across requests. The Guard authorization check may perform
        # network I/O; NEVER hand the generator an object that can change
        # after its resource identity was checked. Isolate the exact snapshot
        # used both for Layer 1 metadata and subsequent model input.
        try:
            original_documents_input = list(documents)
            snapshot_documents = deepcopy(original_documents_input)
            # A custom framework Document can implement __deepcopy__ by
            # returning itself. In that case the former security fix is a
            # no-op: the vector-store can mutate text after the Guard check.
            # Also reject obvious shared nested metadata/node objects.
            for original, snapshot in zip(
                original_documents_input, snapshot_documents, strict=True,
            ):
                if original is snapshot:
                    raise AdapterConfigurationError("Retriever document snapshot was not isolated")
                original_metadata = _metadata(original)
                snapshot_metadata = _metadata(snapshot)
                if original_metadata is snapshot_metadata:
                    raise AdapterConfigurationError("Retriever metadata snapshot was shared")
                original_node = _value(original, "node")
                if original_node is not None and original_node is _value(snapshot, "node"):
                    raise AdapterConfigurationError("Retriever node snapshot was shared")
        except Exception:
            return ProtectedResponse("block", None, "RESOURCE_SNAPSHOT_FAILED")
        try:
            resources = normalize_documents(
                snapshot_documents,
                source_id=self.source_id,
                resource_id_key=self.resource_id_key,
                chunk_id_key=self.chunk_id_key,
            )
        except Exception:
            # Normalization happens outside ProtectedRAG.run's exception
            # boundary. Never throw malformed retrieved metadata into a
            # customer's permissive retry/fallback path.
            return ProtectedResponse("block", None, "RESOURCE_METADATA_REQUIRED")
        by_key: dict[tuple[str, str, str | None], list[_T]] = {}
        for document, resource in zip(snapshot_documents, resources, strict=True):
            by_key.setdefault(self._resource_key(resource), []).append(document)

        def original_documents(authorized: list[RetrievedResource]) -> list[_T]:
            offsets: dict[tuple[str, str, str | None], int] = {}
            selected: list[_T] = []
            for resource in authorized:
                key = self._resource_key(resource)
                values = by_key.get(key, [])
                offset = offsets.get(key, 0)
                if offset < len(values):
                    selected.append(values[offset])
                    offsets[key] = offset + 1
            return selected

        return self.protected_rag.run(
            employee_token=employee_token,
            application_id=application_id,
            request_id=request_id,
            retrieved=resources,
            generate=lambda authorized: generate(original_documents(authorized)),
            regenerate=(
                (lambda authorized: regenerate(original_documents(authorized)))
                if regenerate is not None
                else None
            ),
            source_trace=source_trace,
        )


class LangChainAdapter(RAGAdapter[_T]):
    """Adapter for LangChain ``Document`` objects."""

    capabilities = LANGCHAIN_CAPABILITIES


class LlamaIndexAdapter(RAGAdapter[_T]):
    """Adapter for LlamaIndex nodes with ``metadata`` and ``get_content``."""

    capabilities = LLAMAINDEX_CAPABILITIES


class HaystackAdapter(RAGAdapter[_T]):
    """Adapter for Haystack documents represented as mappings or objects."""

    capabilities = HAYSTACK_CAPABILITIES


def adapter_capability_matrix() -> tuple[AdapterCapabilities, ...]:
    """Return the adapters shipped in this SDK for UI/docs discovery."""
    return (
        GENERIC_CAPABILITIES,
        LANGCHAIN_CAPABILITIES,
        LLAMAINDEX_CAPABILITIES,
        HAYSTACK_CAPABILITIES,
    )
