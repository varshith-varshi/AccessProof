"""A buffered, fail-closed reference integration for customer RAG applications.

The API intentionally makes release dependent on both Guard layers.  It accepts
retrieved objects only when they carry stable source/resource metadata and never
streams model bytes before post-generation verification succeeds.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import uuid4

import httpx

from .attestation import AttestationError, ContentBinding, SourceAttestationVerifier
from .cache import CachedAnswerManifest, CachedAnswerManifestVerifier


@dataclass(frozen=True)
class RetrievedResource:
    source_id: str
    resource_id: str
    chunk_id: str | None = None
    content: str = ""
    derived_id: str | None = None
    derived_type: str = "retrieval"
    # Only useful when independently signed by a trusted source-ingestion
    # service. Untrusted document metadata is NOT authorization evidence.
    content_version: str | None = None
    content_attestation: str | None = None


@dataclass(frozen=True)
class ProtectedResponse:
    decision: str
    response: str | None
    reason: str
    decision_id: str | None = None
    regenerated: bool = False
    # Present only when the Guard has authorization revisions installed.
    authorization_revision: int | None = None
    authorization_revision_hash: str | None = None
    # Only a source-attested trace can support customer Protect certification.
    # Least-privilege defaults keep ad-hoc responses out of certified evidence.
    provenance_level: str = "UNATTESTED_METADATA_ONLY"
    certification_eligible: bool = False


def authorization_revision_binding(
    payload: Mapping[str, Any],
) -> tuple[int | None, str | None]:
    """Read a complete Guard authorization revision binding, if installed."""
    revision = payload.get("authorization_revision")
    revision_hash = payload.get("authorization_revision_hash")
    if revision is None and revision_hash is None:
        return None, None
    if (not isinstance(revision, int) or isinstance(revision, bool) or revision < 1
            or not isinstance(revision_hash, str) or len(revision_hash) != 64
            or any(char not in "0123456789abcdef" for char in revision_hash)):
        raise ValueError("Guard returned an invalid authorization revision")
    return revision, revision_hash


def authorized_resources(
    resources: list[RetrievedResource], layer1: dict[str, Any],
) -> list[RetrievedResource]:
    """Return only the exact resource/chunk combinations approved by Layer 1.

    A resource-level allow (an empty ``chunk_ids`` list) permits every retrieved
    chunk for that resource. When a Guard returns an explicit chunk list, it is
    a narrowing constraint: another chunk with the same file ID must not
    piggyback on the resource allow into model context. Contradictory duplicate
    grants fail closed rather than being merged into a broader allow.
    """
    allowed: dict[tuple[str, str], set[str] | None] = {}
    raw_allowed = layer1.get("allowed", [])
    if not isinstance(raw_allowed, list):
        raise ValueError("Guard returned invalid allowed resources")
    for decision in raw_allowed:
        if not isinstance(decision, dict):
            raise ValueError("Guard returned invalid allowed resource")
        source_id = decision.get("source_id")
        resource_id = decision.get("resource_id")
        chunk_ids = decision.get("chunk_ids", [])
        if (
            not isinstance(source_id, str)
            or not source_id
            or not isinstance(resource_id, str)
            or not resource_id
        ):
            raise ValueError("Guard returned invalid allowed resource")
        if not isinstance(chunk_ids, list) or any(
            not isinstance(value, str) or not value for value in chunk_ids
        ):
            raise ValueError("Guard returned invalid allowed chunk identifiers")
        key = (source_id, resource_id)
        candidate = None if not chunk_ids else set(chunk_ids)
        if key in allowed and allowed[key] != candidate:
            raise ValueError("Guard returned conflicting grant scopes")
        allowed[key] = candidate

    authorized: list[RetrievedResource] = []
    for resource in resources:
        chunks = allowed.get((resource.source_id, resource.resource_id), set())
        if chunks is None or (resource.chunk_id is not None and resource.chunk_id in chunks):
            authorized.append(resource)
    return authorized


class GuardClient:
    def __init__(self, base_url: str, *, timeout_seconds: float = 10.0, client: httpx.Client | None = None, multisource: bool = False) -> None:
        self.base_url = base_url.rstrip("/")
        self.multisource = multisource
        self.client = client or httpx.Client(timeout=timeout_seconds, follow_redirects=False, trust_env=False)
        self._owns_client = client is None

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    def health(self, *, application_id: str | None = None) -> dict[str, Any]:
        """Return global or app-scoped Guard health without employee data."""
        response = self.client.get(
            f"{self.base_url}/health",
            params={"application_id": application_id} if application_id is not None else None,
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("status"), str):
            raise ValueError("Guard returned an invalid health response")
        return data

    def authorization_scope(self, *, employee_token: str, application_id: str, request_id: str) -> dict[str, Any]:
        """Read the allowed resource identifiers for scoped ANN retrieval."""
        response = self.client.post(
            f"{self.base_url}/guard/v1/authorization-scope",
            headers={"Authorization": f"Bearer {employee_token}"},
            json={"application_id": application_id, "request_id": request_id},
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("decision"), str):
            raise ValueError("Guard returned an invalid authorization scope")
        return data

    def multisource_authorization_scope(
        self, *, employee_token: str, application_id: str,
        request_id: str, source_ids: list[str],
    ) -> dict[str, Any]:
        """Source-qualified allowset for compatible pre-retrieval ANN search."""
        if not self.multisource or not source_ids:
            raise ValueError("MULTISOURCE_GUARD_V2_REQUIRED")
        response = self.client.post(
            f"{self.base_url}/guard/v2/authorization-scope",
            headers={"Authorization": f"Bearer {employee_token}"},
            json={"application_id": application_id, "request_id": request_id,
                  "source_ids": source_ids},
        )
        response.raise_for_status()
        data = response.json()
        if (not isinstance(data, dict) or data.get("mode") != "protect"
                or data.get("scope_complete") is not True
                or data.get("decision") not in {"allow", "block"}
                or not isinstance(data.get("sources"), list)):
            raise ValueError("INVALID_MULTISOURCE_AUTHORIZATION_SCOPE")
        returned_sources = data["sources"]
        if (len(source_ids) != len(set(source_ids))
                or len(returned_sources) != len(source_ids)
                or any(not isinstance(item, dict)
                       or not isinstance(item.get("source_id"), str)
                       or not isinstance(item.get("allowed_resource_ids"), list)
                       or any(not isinstance(rid, str) or not rid
                              for rid in item["allowed_resource_ids"])
                       for item in returned_sources)
                or {item["source_id"] for item in returned_sources} != set(source_ids)):
            raise ValueError("INVALID_MULTISOURCE_AUTHORIZATION_SCOPE")
        authorization_revision_binding(data)
        return data

    def filter_resources(self, *, employee_token: str, application_id: str, request_id: str, resources: list[RetrievedResource]) -> dict[str, Any]:
        payload = {"application_id": application_id, "request_id": request_id, "resources": [
            {"source_id": item.source_id, "resource_id": item.resource_id, "scope": "read", "chunk_ids": [item.chunk_id] if item.chunk_id else [],
             "content_version": item.content_version}
            for item in resources
        ]}
        response = self.client.post(f"{self.base_url}/guard/v{2 if self.multisource else 1}/filter-resources", headers={"Authorization": f"Bearer {employee_token}"}, json=payload)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("decision_id"), str):
            raise ValueError("Guard returned an invalid Layer 1 decision")
        return data

    def check_output(self, *, employee_token: str, application_id: str, request_id: str, decision_id: str, resources: list[RetrievedResource], additional_decision_ids: list[str] | None = None) -> dict[str, Any]:
        resource_ids = sorted({item.resource_id for item in resources})
        provenance = [{
            "derived_id": item.derived_id or item.chunk_id or item.resource_id,
            "derived_type": item.derived_type,
            "source_resource_ids": [item.resource_id],
        } for item in resources]
        if self.multisource:
            if additional_decision_ids:
                raise ValueError("MULTISOURCE_LATE_DEPENDENCIES_NOT_SUPPORTED")
            scoped = [{
                "source_id": item.source_id, "resource_id": item.resource_id,
                "chunk_id": item.chunk_id,
                "content_version": item.content_version,
            } for item in resources]
            output = {
                "decision_id": decision_id, "application_id": application_id,
                "request_id": request_id, "used_resources": scoped,
                "provenance": scoped,
            }
            endpoint = "v2"
        else:
            output = {
                "decision_id": decision_id, "application_id": application_id,
                "request_id": request_id, "used_resource_ids": resource_ids,
                "provenance": provenance,
                "additional_decision_ids": additional_decision_ids or [],
            }
            endpoint = "v1"
        response = self.client.post(
            f"{self.base_url}/guard/{endpoint}/check-output",
            headers={"Authorization": f"Bearer {employee_token}"}, json=output,
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("decision"), str):
            raise ValueError("Guard returned an invalid Layer 2 decision")
        return data


class AuthorizationGuard(Protocol):
    """The two Guard calls ProtectedRAG needs (GuardClient, ParticipantAwareGuard)."""

    def filter_resources(self, *, employee_token: str, application_id: str, request_id: str,
                         resources: list[RetrievedResource]) -> dict[str, Any]: ...

    def check_output(self, *, employee_token: str, application_id: str, request_id: str,
                     decision_id: str, resources: list[RetrievedResource],
                     additional_decision_ids: list[str] | None = None) -> dict[str, Any]: ...


class ProtectedRAG:
    """Runs retrieve → Layer 1 → model buffer → Layer 2 → release.

    ``generate`` receives only authorized resources.  A generator response is
    fully bounded and collected before Layer 2, so Protect mode never leaks a
    first streamed token before authorization completes.

    Protect release requires a pinned source-attestation verifier. Without one,
    ``run`` fails closed; callers of legacy metadata-only integrations must
    explicitly enable ``allow_unattested_metadata`` and accept that such
    responses are ineligible for certification.
    """
    def __init__(
        self, guard: AuthorizationGuard, *, max_response_bytes: int = 1_000_000,
        max_regenerations: int = 0,
        provenance_verifier: SourceAttestationVerifier | None = None,
        allow_unattested_metadata: bool = False,
    ) -> None:
        self.guard = guard
        self.max_response_bytes = max_response_bytes
        # Retained for source compatibility only. V3 Protect never regenerates
        # automatically after a Layer 2 rejection.
        self.max_regenerations = 0
        if provenance_verifier is not None and allow_unattested_metadata:
            raise ValueError("Attested and unattested provenance modes are mutually exclusive")
        # A verifier is installed only on source-attested, certifiable routes.
        # Without one, Protect must block rather than trust application-supplied
        # metadata. The legacy flag is an explicit, non-certified escape hatch
        # for existing metadata-only integrations and must never be used to
        # produce customer certification evidence.
        self.provenance_verifier = provenance_verifier
        self.allow_unattested_metadata = allow_unattested_metadata

    def _verify_source_content(self, resources: list[RetrievedResource], application_id: str) -> bool:
        if self.provenance_verifier is None:
            return False
        for resource in resources:
            if resource.content_version is None:
                return False
            try:
                self.provenance_verifier.verify(
                    ContentBinding(
                        tenant_id=self.provenance_verifier.tenant_id,
                        application_id=application_id,
                        source_id=resource.source_id,
                        resource_id=resource.resource_id,
                        chunk_id=resource.chunk_id,
                        content_version=resource.content_version,
                        content=resource.content,
                    ),
                    resource.content_attestation,
                )
            except (AttestationError, ValueError):
                return False
        return True

    @property
    def _provenance_level(self) -> str:
        return ("SOURCE_ATTESTED" if self.provenance_verifier is not None
                else "UNATTESTED_METADATA_ONLY")

    @staticmethod
    def _revision_binding(payload: Mapping[str, Any]) -> tuple[int | None, str | None]:
        return authorization_revision_binding(payload)

    @staticmethod
    def _authorized(resources: list[RetrievedResource], layer1: dict[str, Any]) -> list[RetrievedResource]:
        return authorized_resources(resources, layer1)

    def verify_cached_answer(
        self, *, employee_token: str, application_id: str, manifest: CachedAnswerManifest,
        manifest_token: str | None, manifest_verifier: CachedAnswerManifestVerifier,
        request_id: str | None = None,
    ) -> ProtectedResponse:
        """Authorize a signed answer-cache hit for the current employee.

        This never invokes a model and never trusts a historical allow decision.
        Every dependency is cryptographically bound then checked by Layer 1 and
        Layer 2 under the employee making this request.
        """
        try:
            if application_id != manifest.application_id or self.provenance_verifier is None:
                return ProtectedResponse("block", None, "CACHE_MANIFEST_BINDING_REQUIRED")
            # A cache hit is an output delivery just like fresh generation.
            # Never let it bypass the size cap enforced by _buffer().
            if len(manifest.answer.encode("utf-8")) > self.max_response_bytes:
                return ProtectedResponse("block", None, "CACHE_RESPONSE_TOO_LARGE")
            manifest_verifier.verify(manifest, manifest_token)
            resources: list[RetrievedResource] = []
            for dependency in manifest.dependencies:
                self.provenance_verifier.verify_digest(
                    tenant_id=manifest.tenant_id, application_id=application_id,
                    source_id=dependency.source_id, resource_id=dependency.resource_id,
                    chunk_id=dependency.chunk_id, content_version=dependency.content_version,
                    content_digest=dependency.content_digest, token=dependency.content_attestation,
                )
                resources.append(RetrievedResource(
                    source_id=dependency.source_id, resource_id=dependency.resource_id,
                    chunk_id=dependency.chunk_id, derived_type=dependency.derived_type,
                    content_version=dependency.content_version,
                ))
            request_id = request_id or str(uuid4())
            layer1 = self.guard.filter_resources(
                employee_token=employee_token, application_id=application_id,
                request_id=request_id, resources=resources,
            )
            if layer1.get("mode", "protect") != "protect" or layer1.get("decision") != "allow":
                return ProtectedResponse("block", None, "CACHE_DEPENDENCY_NOT_AUTHORIZED", str(layer1.get("decision_id", "")))
            authorized = self._authorized(resources, layer1)
            if len(authorized) != len(resources):
                return ProtectedResponse("block", None, "CACHE_DEPENDENCY_NOT_AUTHORIZED", str(layer1.get("decision_id", "")))
            current_revision, current_revision_hash = self._revision_binding(layer1)
            if current_revision is not None:
                # The answer was generated under an exact authorization state.
                # Serving it after any ACL/directory/policy change would mix a
                # historical answer with a new state, so require the write-time
                # revision and reject stale or unbound entries.
                if manifest.authorization_revision is None:
                    return ProtectedResponse("block", None, "CACHE_REVISION_BINDING_REQUIRED", str(layer1.get("decision_id", "")))
                if (manifest.authorization_revision != current_revision
                        or manifest.authorization_revision_hash != current_revision_hash):
                    return ProtectedResponse("block", None, "CACHE_AUTHORIZATION_REVISION_STALE", str(layer1.get("decision_id", "")))
            layer2 = self.guard.check_output(
                employee_token=employee_token, application_id=application_id, request_id=request_id,
                decision_id=str(layer1["decision_id"]), resources=resources,
            )
            if layer2.get("decision") != "allow":
                return ProtectedResponse("block", None, "CACHE_OUTPUT_NOT_AUTHORIZED", str(layer1["decision_id"]))
            layer2_revision, layer2_revision_hash = self._revision_binding(layer2)
            # A Guard that advertised a revision at Layer 1 must prove that
            # Layer 2 checked that same state. An omitted revision is not a
            # successful re-authorization, even if the response says "allow".
            if (current_revision is None) != (layer2_revision is None):
                return ProtectedResponse("block", None, "AUTHORIZATION_REVISION_MISSING", str(layer1["decision_id"]))
            if (current_revision is not None
                    and (current_revision, current_revision_hash)
                    != (layer2_revision, layer2_revision_hash)):
                return ProtectedResponse("block", None, "AUTHORIZATION_REVISION_CHANGED", str(layer1["decision_id"]))
            if layer2_revision is not None:
                current_revision, current_revision_hash = layer2_revision, layer2_revision_hash
            return ProtectedResponse(
                "allow", manifest.answer, str(layer2.get("reason", "CACHE_ALLOWED")),
                str(layer1["decision_id"]),
                authorization_revision=current_revision,
                authorization_revision_hash=current_revision_hash,
                provenance_level="SOURCE_ATTESTED",
                certification_eligible=True,
            )
        except (AttestationError, ValueError, httpx.HTTPError):
            return ProtectedResponse("block", None, "CACHE_MANIFEST_INVALID")
        except Exception:
            return ProtectedResponse("block", None, "CACHE_PROTECTION_FAILED")

    def _buffer(self, generated: str | Iterable[str]) -> str:
        # Count UTF-8 bytes incrementally. Re-encoding and concatenating the
        # entire response for every streamed chunk causes quadratic work.
        parts = [generated] if isinstance(generated, str) else generated
        buffered: list[str] = []
        total_bytes = 0
        for part in parts:
            if not isinstance(part, str):
                raise TypeError("The model callback must produce text")
            total_bytes += len(part.encode("utf-8"))
            if total_bytes > self.max_response_bytes:
                raise ValueError("Model response exceeds AccessProof response buffer limit")
            buffered.append(part)
        return "".join(buffered)

    def run(self, *, employee_token: str, application_id: str, retrieved: list[RetrievedResource], generate: Callable[[list[RetrievedResource]], str | Iterable[str]], request_id: str | None = None, regenerate: Callable[[list[RetrievedResource]], str | Iterable[str]] | None = None, source_trace: Callable[[], list[RetrievedResource]] | None = None) -> ProtectedResponse:
        """Return an explicit fail-closed decision on any Guard/adapter failure.

        ``regenerate`` remains accepted for backwards compatibility but is never
        invoked by V3 Protect mode.

        Exceptions must not escape to a customer's permissive HTTP fallback or
        retry handler, which may otherwise return the buffered model output.
        Never include untrusted document/model contents in the error reason.
        """
        try:
            # A caller may reuse and mutate its vector-store result list while
            # Guard performs network I/O. Freeze collection membership before
            # the authorization snapshot. RetrievedResource is immutable.
            input_snapshot = list(retrieved)
            return self._run_checked(
                employee_token=employee_token, application_id=application_id,
                retrieved=input_snapshot, generate=generate, request_id=request_id,
                source_trace=source_trace,
            )
        except httpx.HTTPStatusError as exc:
            # D-20: still an explicit block, but report WHY. A rejected
            # identity or a Guard policy refusal is not a Guard outage, and
            # must not be indistinguishable from one in responses or evidence.
            status = exc.response.status_code if exc.response is not None else 0
            if status == 401:
                return ProtectedResponse("block", None, "IDENTITY_REJECTED")
            if status == 403:
                return ProtectedResponse("block", None, "GUARD_POLICY_DENIED")
            return ProtectedResponse("block", None, "GUARD_REQUEST_FAILED")
        except httpx.HTTPError:
            return ProtectedResponse("block", None, "GUARD_REQUEST_FAILED")
        except Exception:
            return ProtectedResponse("block", None, "PROTECTION_PIPELINE_FAILED")

    def _run_checked(self, *, employee_token: str, application_id: str, retrieved: list[RetrievedResource], generate: Callable[[list[RetrievedResource]], str | Iterable[str]], request_id: str | None = None, source_trace: Callable[[], list[RetrievedResource]] | None = None) -> ProtectedResponse:
        if not retrieved:
            return ProtectedResponse("block", None, "NO_RETRIEVED_RESOURCES")
        if any(not item.source_id or not item.resource_id for item in retrieved):
            return ProtectedResponse("block", None, "RESOURCE_METADATA_REQUIRED")
        request_id = request_id or str(uuid4())
        layer1 = self.guard.filter_resources(employee_token=employee_token, application_id=application_id, request_id=request_id, resources=retrieved)
        # An upstream/adapter mode mismatch must never weaken Protect into
        # observational Shadow. Older adapters without a mode are treated as
        # Protect; they must never obtain Shadow-style release semantics.
        guard_mode = layer1.get("mode", "protect")
        # Certified source-attested routes must never silently degrade into a
        # release-permitting observational mode.
        if self.provenance_verifier is not None and guard_mode != "protect":
            return ProtectedResponse(
                "block", None, "ATTESTED_ROUTE_REQUIRES_PROTECT",
                str(layer1.get("decision_id", "")),
            )
        # A Protect Guard legitimately returns ``block`` when no retrieved
        # resource is authorized.  Treating that as a protocol mismatch hid a
        # successful revocation behind an unrelated adapter error.
        expected_l1 = {"allow", "block"} if guard_mode == "protect" else {"would_allow", "would_block"}
        if guard_mode not in {"protect", "shadow"} or layer1.get("decision") not in expected_l1:
            return ProtectedResponse("block", None, "GUARD_MODE_MISMATCH", str(layer1.get("decision_id", "")))
        revision, revision_hash = self._revision_binding(layer1)
        if guard_mode == "protect" and layer1["decision"] == "block":
            # A DENY cannot be overridden by a contradictory/malformed
            # allowlist. Preserve the existing denied-resource reason.
            reason = ("GUARD_DECISION_CONTRADICTION"
                      if layer1.get("allowed") else "NO_AUTHORIZED_RESOURCES")
            return ProtectedResponse("block", None, reason, str(layer1["decision_id"]))
        authorized = self._authorized(retrieved, layer1)
        if not authorized:
            return ProtectedResponse("block", None, "NO_AUTHORIZED_RESOURCES", str(layer1["decision_id"]))
        # Without a pinned ingestion verifier the SDK cannot distinguish trusted
        # document bytes from application-supplied text. Protect must fail
        # closed before generation; only an explicit legacy opt-in may release
        # unattested answers, and those responses are permanently ineligible for
        # certification.
        if (self.provenance_verifier is None and guard_mode == "protect"
                and not self.allow_unattested_metadata):
            return ProtectedResponse(
                "block", None, "SOURCE_CONTENT_ATTESTATION_REQUIRED",
                str(layer1["decision_id"]),
            )
        # In source-attested mode, verify trusted ingestion signatures over
        # the exact bytes before handing even one chunk to the generator.
        if self.provenance_verifier is not None and not self._verify_source_content(
            authorized, application_id
        ):
            return ProtectedResponse("block", None, "SOURCE_CONTENT_ATTESTATION_FAILED", str(layer1["decision_id"]))
        # Only a trusted application-owned trace can establish complete lineage.
        # The initial retrieval list alone does not account for cached inputs,
        # tool results, or chat context; never infer trace completeness from it.
        if source_trace is None and guard_mode == "protect":
            return ProtectedResponse("block", None, "PROVENANCE_TRACE_REQUIRED", str(layer1["decision_id"]))
        answer = self._buffer(generate(authorized))
        # Only trusted RAG orchestration/retrieval metadata may supply the
        # real lineage. Never infer it from LLM answer text or citations.
        try:
            traced = list(source_trace()) if source_trace is not None else authorized
        except Exception:
            return ProtectedResponse("block", None, "PROVENANCE_MISSING", str(layer1["decision_id"]))
        if not traced or any(
            not isinstance(item, RetrievedResource) or not item.source_id or not item.resource_id
            for item in traced
        ):
            return ProtectedResponse("block", None, "PROVENANCE_MISSING", str(layer1["decision_id"]))
        if self.provenance_verifier is not None and not self._verify_source_content(
            traced, application_id
        ):
            return ProtectedResponse("block", None, "SOURCE_TRACE_ATTESTATION_FAILED", str(layer1["decision_id"]))
        if self.provenance_verifier is not None:
            # Reporting only one of several generator inputs is not a complete
            # lineage trace. Require every signed input used at generation to
            # appear with the SAME bound bytes and attestation in the trace.
            def trace_key(item: RetrievedResource) -> tuple[str, str, str | None, str, str | None, str | None]:
                return (item.source_id, item.resource_id, item.chunk_id,
                        item.content, item.content_version, item.content_attestation)
            observed = {trace_key(item) for item in traced}
            if any(trace_key(item) not in observed for item in authorized):
                return ProtectedResponse("block", None, "INCOMPLETE_GENERATOR_SOURCE_TRACE", str(layer1["decision_id"]))
        # Reuse the original Layer 1 scope for provenance matching, including
        # explicit chunk constraints. A newly observed chunk of an already
        # approved document is still a late source when only particular chunks
        # were approved. File-level allows (empty chunk_ids) remain valid for
        # every chunk of that file.
        first_allowed = self._authorized(traced, layer1)
        first_allowed_keys = {
            (item.source_id, item.resource_id, item.chunk_id)
            for item in first_allowed
        }
        late = [
            item for item in traced
            if (item.source_id, item.resource_id, item.chunk_id) not in first_allowed_keys
        ]
        additional_decision_ids: list[str] = []
        late_would_block = False
        if late:
            # A cached/tool source that appeared after initial retrieval gets
            # its own real Layer 1 authorization before release.
            additional = self.guard.filter_resources(
                employee_token=employee_token, application_id=application_id,
                request_id=request_id, resources=late,
            )
            # Do not widen a partial chunk approval to an entire document:
            # the Guard may allow a different chunk of the same resource.
            all_late_authorized = len(self._authorized(late, additional)) == len(late)
            if (additional.get("mode", "protect") != guard_mode
                    or additional.get("decision") not in (
                        {"allow"} if guard_mode == "protect" else expected_l1
                    )
                    or not all_late_authorized):
                return ProtectedResponse("block", None, "ADDITIONAL_SOURCE_NOT_AUTHORIZED", str(layer1["decision_id"]))
            late_would_block = additional["decision"] == "would_block"
            additional_decision_ids.append(str(additional["decision_id"]))
        layer2 = self.guard.check_output(
            employee_token=employee_token, application_id=application_id,
            request_id=request_id, decision_id=str(layer1["decision_id"]),
            resources=traced, additional_decision_ids=additional_decision_ids,
        )
        valid_layer2 = ({"allow"} if guard_mode == "protect" else {"would_allow", "would_block"})
        if layer2["decision"] in valid_layer2:
            layer2_revision, layer2_revision_hash = self._revision_binding(layer2)
            if guard_mode == "protect" and ((revision is None) != (layer2_revision is None)):
                # An omitted revision cannot authenticate a Layer 2 release
                # against Layer 1's authorization snapshot.
                return ProtectedResponse("block", None, "AUTHORIZATION_REVISION_MISSING", str(layer1["decision_id"]))
            if (guard_mode == "protect" and revision is not None
                    and (revision, revision_hash) != (layer2_revision, layer2_revision_hash)):
                # The authorization state changed between Layer 1 and release.
                # A conformance-correct Guard also blocks this; never release
                # when the two decisions disagree on the state they cover.
                return ProtectedResponse("block", None, "AUTHORIZATION_REVISION_CHANGED", str(layer1["decision_id"]))
            if layer2_revision is not None:
                revision, revision_hash = layer2_revision, layer2_revision_hash
            # Only an explicitly Shadow application may release would-block
            # output. Protect can release only a positive Layer 2 allow.
            overall = ("would_block" if guard_mode == "shadow" and
                       (layer1["decision"] == "would_block" or late_would_block)
                       else str(layer2["decision"]))
            return ProtectedResponse(
                overall, answer, str(layer2["reason"]), str(layer1["decision_id"]),
                authorization_revision=revision,
                authorization_revision_hash=revision_hash,
                provenance_level=self._provenance_level,
                certification_eligible=self.provenance_verifier is not None,
            )
        if layer2["decision"] in {"would_allow", "would_block"}:
            return ProtectedResponse("block", None, "GUARD_MODE_MISMATCH", str(layer1["decision_id"]))
        # V3 deliberately does not retry or regenerate after a Layer 2 rejection.
        # A customer may start a wholly new request after addressing its own
        # retrieval state, but this protected request has exactly one model call.
        return ProtectedResponse(str(layer2["decision"]), None, str(layer2["reason"]), str(layer1["decision_id"]))
