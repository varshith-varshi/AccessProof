"""Continuous trusted-ingestion refresh: manifests, refresher, Gateway
distribution and the remote-RAG subscriber.

Covers: refresh before expiry across many TTL cycles, document modification and
deletion, permission change detection without reauthorization, expired
attestations, invalid signatures and tampered manifests, rollback, network
outage + recovery, concurrent refreshers, subscriber restart, cross-tenant
isolation, and that served evidence never bypasses Guard Layer 1/2.
"""
from __future__ import annotations

import base64
import json
import sys
import threading
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apps.gateway.accessproof_gateway.evidence_distribution import EvidenceDistribution
from packages.rag_core.attestation import ContentBinding, SourceAttestationSigner
from packages.rag_core.evidence_manifest import ManifestError, build_manifest, verify_manifest
from packages.rag_core.evidence_refresher import EvidencePublisher, EvidenceRefresher, RefreshPolicy

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "integrations/rag-clients/python"))
from accessproof_rag import ProtectionUnavailable  # noqa: E402
from accessproof_rag.evidence import EvidenceSubscriber, EvidenceUnavailable  # noqa: E402

T, A, S = "tenant-a", "hr-assistant", "sp-source-1"
TTL = 1800


def b64pub(key: Ed25519PrivateKey) -> str:
    return base64.urlsafe_b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,
                                                                  serialization.PublicFormat.Raw)).rstrip(b"=").decode()


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class Source:
    """Fake SharePoint: current documents; attests in-cycle with the ingestion key."""

    def __init__(self, key, clock, tenant=T, app=A, source=S):
        self.signer = SourceAttestationSigner(key_id="ingest-1", private_key=key)
        self.clock, self.tenant, self.app, self.source = clock, tenant, app, source
        self.docs = {"doc-fin": ("v1", "finance budget synthetic"), "doc-eng": ("v1", "engineering plan synthetic")}
        self.perms = {"doc-fin": "p1", "doc-eng": "p1"}
        self.fail = 0

    def __call__(self):
        if self.fail:
            self.fail -= 1
            raise ConnectionError("graph unreachable")
        chunks = []
        for rid, (ver, text) in self.docs.items():
            cid = f"{rid}:{ver}:c0"
            att = self.signer.issue(ContentBinding(tenant_id=self.tenant, application_id=self.app, source_id=self.source,
                                                   resource_id=rid, chunk_id=cid, content_version=ver, content=text),
                                    ttl_seconds=TTL, now=int(self.clock()))
            chunks.append({"resource_id": rid, "chunk_id": cid, "content_version": ver, "content": text, "content_attestation": att})
        return {"documents": [{"resource_id": r, "content_version": v, "name": r} for r, (v, _t) in self.docs.items()],
                "chunks": chunks, "permissions": dict(self.perms)}


@pytest.fixture()
def env(tmp_path):
    clock = Clock()
    ingest, mkey = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    source = Source(ingest, clock)
    pub = EvidencePublisher(tmp_path / "pub", T, A, S)
    refresher = EvidenceRefresher(adapter=source, publisher=pub, tenant_id=T, application_id=A, source_id=S,
                                  attestation_keys={"ingest-1": ingest.public_key()}, manifest_key=mkey,
                                  manifest_key_id="manifest-1", policy=RefreshPolicy(interval_seconds=600),
                                  clock=clock, sleep=lambda s: None, health_path=tmp_path / "health.json")
    dist = EvidenceDistribution(tmp_path / "pub", {"manifest-1": mkey.public_key()})

    class GW:  # the subscriber's transport = the Gateway distribution logic
        down = False

        def fetch_evidence(self, source_id):
            if GW.down:
                raise ProtectionUnavailable("GATEWAY_UNREACHABLE:URLError")
            status, payload = dist.serve(tenant_id=T, application_id=A, source_id=source_id,
                                         attestation_keys={"ingest-1": ingest.public_key()}, now=int(clock()))
            if status != 200:
                raise ProtectionUnavailable(str(payload), status)
            return payload

    def subscriber(cache=None):
        return EvidenceSubscriber(GW(), source_id=S, tenant_id=T, application_id=A,
                                  manifest_keys={"manifest-1": b64pub(mkey)}, attestation_keys={"ingest-1": b64pub(ingest)},
                                  cache_path=str(cache) if cache else None, interval_seconds=300, clock=clock,
                                  sleep=lambda s: None)
    return {"clock": clock, "source": source, "pub": pub, "refresher": refresher, "dist": dist, "GW": GW,
            "subscriber": subscriber, "ingest": ingest, "mkey": mkey, "tmp": tmp_path}


def test_refresh_before_expiry_keeps_remote_rag_working_across_many_ttl_cycles(env):
    sub = env["subscriber"]()
    seqs, expiries = [], []
    for _cycle in range(12):                            # 12 x 10 min = 2 h = 4 attestation lifetimes
        assert env["refresher"].refresh_once()["event"] == "EVIDENCE_REFRESHED"
        assert sub.refresh_once()["status"] == "OK"
        assert {c.resource_id for c in sub.search("finance budget")} == {"doc-fin"}
        m = sub.current(); seqs.append(m["seq"]); expiries.append(m["expires_at"])
        assert m["expires_at"] - env["clock"]() <= TTL       # never more life than one TTL
        env["clock"].t += 600
    assert seqs == list(range(1, 13)) and expiries == sorted(expiries)
    assert env["refresher"].health()["state"] == "OK"


def test_refresh_failure_never_extends_and_remote_rag_fails_closed(env):
    env["refresher"].refresh_once()
    sub = env["subscriber"](); sub.refresh_once()
    original = sub.current()["expires_at"]
    env["source"].fail = 10**6                           # SharePoint/Graph down for good
    for _ in range(4):
        env["clock"].t += 600
        assert env["refresher"].refresh_once()["event"] == "EVIDENCE_REFRESH_FAILED"
        sub.refresh_once()
    assert env["pub"].read_current()["expires_at"] == original       # nothing re-signed or extended
    h = env["refresher"].health()
    assert h["state"] == "EXPIRED" and h["alert"] and h["consecutive_failures"] == 4
    with pytest.raises(EvidenceUnavailable, match="EVIDENCE_EXPIRED"):
        sub.search("finance")
    assert env["dist"].serve(tenant_id=T, application_id=A, source_id=S, attestation_keys={"ingest-1": env["ingest"].public_key()},
                             now=int(env["clock"]()))[1] == "EVIDENCE_EXPIRED"


def test_bounded_retries_then_recovery_after_transient_source_outage(env):
    env["source"].fail = 2                               # two failures, then the 3rd attempt works
    out = env["refresher"].refresh_once()
    assert out["event"] == "EVIDENCE_REFRESHED" and out["attempts"] == 3
    env["source"].fail = 100
    assert env["refresher"].refresh_once()["event"] == "EVIDENCE_REFRESH_FAILED"   # 1 + 3 retries, bounded
    assert env["source"].fail == 96
    env["source"].fail = 0
    assert env["refresher"].refresh_once()["event"] == "EVIDENCE_REFRESHED"
    assert env["refresher"].health()["consecutive_failures"] == 0


def test_alert_before_expiry_and_schedule_pulled_forward(env):
    env["refresher"].refresh_once()
    env["clock"].t += TTL - 500
    h = env["refresher"].health()
    assert h["state"] == "OK" and h["alert"] is True and 0 < h["seconds_remaining"] <= 600
    # The next cycle is pulled forward to run before expiry (minus the safety margin).
    assert env["refresher"].next_delay() <= h["seconds_remaining"] - 300 + 1e-6


def test_document_modification_and_deletion_are_reflected(env):
    env["refresher"].refresh_once()
    env["source"].docs["doc-fin"] = ("v2", "finance budget revised synthetic")
    ev = env["refresher"].refresh_once()
    assert ev["updated"] == ["doc-fin"]
    del env["source"].docs["doc-eng"]
    ev = env["refresher"].refresh_once()
    assert ev["deleted"] == ["doc-eng"]
    sub = env["subscriber"](); sub.refresh_once()
    chunks = sub.chunks()
    assert [(c.resource_id, c.content_version) for c in chunks] == [("doc-fin", "v2")]
    assert all("revised" in c.content for c in chunks)


def test_permission_change_is_detected_but_grants_nothing(env):
    env["refresher"].refresh_once()
    env["source"].perms["doc-fin"] = "p2-alice-removed"
    ev = env["refresher"].refresh_once()
    assert ev["permissions_changed"] == ["doc-fin"]
    m = env["pub"].read_current()
    # Provenance only: no subject, grant, role or decision appears anywhere.
    text = json.dumps(m)
    for word in ("allow", "subject", "grant", "role", "decision", "principal"):
        assert word not in text.lower()


def test_build_refuses_bad_or_stale_attestations(env):
    snap = env["source"]()
    common = dict(tenant_id=T, application_id=A, source_id=S, seq=1, documents=snap["documents"],
                  attestation_keys={"ingest-1": env["ingest"].public_key()}, manifest_key=env["mkey"],
                  manifest_key_id="manifest-1", previous_sha256="0" * 64)
    bad = [dict(c) for c in snap["chunks"]]; bad[0]["content"] += " tampered"
    with pytest.raises(ManifestError, match="BINDING_MISMATCH"):
        build_manifest(chunks=bad, now=int(env["clock"]()), **common)
    with pytest.raises(ManifestError, match="NOT_FRESH"):          # about to expire: refuse to republish
        build_manifest(chunks=snap["chunks"], now=int(env["clock"]()) + TTL - 60, **common)
    rogue = SourceAttestationSigner(key_id="ingest-1", private_key=Ed25519PrivateKey.generate())
    forged = [dict(c) for c in snap["chunks"]]
    forged[0]["content_attestation"] = rogue.issue(ContentBinding(tenant_id=T, application_id=A, source_id=S, resource_id="doc-fin",
                                                                  chunk_id=forged[0]["chunk_id"], content_version="v1",
                                                                  content=forged[0]["content"]), ttl_seconds=TTL, now=int(env["clock"]()))
    with pytest.raises(ManifestError, match="SIGNATURE_INVALID"):
        build_manifest(chunks=forged, now=int(env["clock"]()), **common)
    with pytest.raises(ManifestError, match="NOT_FRESH"):          # TTL above policy is refused
        build_manifest(chunks=snap["chunks"], now=int(env["clock"]()), max_ttl=900, **common)


@pytest.mark.parametrize("tamper", ["content", "drop_chunk", "add_document", "expires_at", "signature", "seq_rollback",
                                    "other_manifest_key"])
def test_tampered_or_invalid_manifests_are_rejected(env, tamper):
    env["refresher"].refresh_once(); env["refresher"].refresh_once()
    m = env["pub"].read_current()
    keys = dict(manifest_keys={"manifest-1": env["mkey"].public_key()},
                attestation_keys={"ingest-1": env["ingest"].public_key()}, tenant_id=T, application_id=A, source_id=S,
                now=int(env["clock"]()))
    verify_manifest(m, **keys)
    bad = json.loads(json.dumps(m))
    if tamper == "content":
        bad["chunks"][0]["content"] += "x"
    elif tamper == "drop_chunk":
        bad["chunks"].pop()
    elif tamper == "add_document":
        bad["documents"].append({"resource_id": "doc-x", "content_version": "v1", "name": "x", "deleted": False})
    elif tamper == "expires_at":
        bad["expires_at"] += 3600
    elif tamper == "signature":
        bad["signature"] = bad["signature"][:-4] + "AAAA"
    elif tamper == "seq_rollback":
        with pytest.raises(ManifestError, match="ROLLBACK"):
            verify_manifest(m, min_seq=m["seq"] + 1, **keys)
        return
    elif tamper == "other_manifest_key":
        body = {k: v for k, v in bad.items() if k != "signature"}
        from packages.rag_core.evidence_manifest import _b64, canonical
        bad["signature"] = _b64(Ed25519PrivateKey.generate().sign(canonical(body)))
    with pytest.raises(ManifestError):
        verify_manifest(bad, **keys)


def test_signed_manifest_claiming_longer_life_than_its_attestations_is_rejected(env):
    env["refresher"].refresh_once()
    m = {k: v for k, v in env["pub"].read_current().items() if k != "signature"}
    m["expires_at"] += 600
    from packages.rag_core.evidence_manifest import _b64, canonical
    m["signature"] = _b64(env["mkey"].sign(canonical(m)))            # even with the real manifest key
    with pytest.raises(ManifestError, match="EXPIRY_INCONSISTENT"):
        verify_manifest(m, manifest_keys={"manifest-1": env["mkey"].public_key()},
                        attestation_keys={"ingest-1": env["ingest"].public_key()}, tenant_id=T, application_id=A,
                        source_id=S, now=int(env["clock"]()))


def test_concurrent_refreshers_publish_atomically_with_unique_contiguous_seq(env):
    errors = []

    def run():
        try:
            for _ in range(5):
                env["refresher"].refresh_once()
        except Exception as exc:  # pragma: no cover
            errors.append(exc)
    threads = [threading.Thread(target=run) for _ in range(6)]
    [t.start() for t in threads]; [t.join() for t in threads]
    assert not errors
    cur = env["pub"].read_current()
    assert cur["seq"] == 30
    hist = sorted(env["pub"].dir.glob("seq-*.json"))
    seqs = [json.loads(p.read_bytes())["seq"] for p in hist]
    assert seqs == list(range(26, 31))
    # chain: each manifest names its predecessor
    from packages.rag_core.evidence_manifest import manifest_sha256
    for prev, nxt in zip(hist, hist[1:]):
        assert json.loads(nxt.read_bytes())["previous_sha256"] == manifest_sha256(json.loads(prev.read_bytes()))
    assert not list(env["pub"].dir.glob(".*.tmp"))


def test_network_outage_then_recovery_for_remote_rag(env):
    env["refresher"].refresh_once()
    sub = env["subscriber"](); sub.refresh_once()
    env["GW"].down = True
    env["clock"].t += 600; env["refresher"].refresh_once()
    r = sub.refresh_once()
    assert r["status"] == "FAILED" and sub.health()["state"] == "DEGRADED"
    assert sub.search("finance")                                   # still within the old manifest's life
    assert sub.next_delay() <= 22.5                                # retries soon
    env["clock"].t += TTL                                          # outage outlasts the evidence
    env["refresher"].refresh_once()
    with pytest.raises(EvidenceUnavailable):
        sub.search("finance")
    env["GW"].down = False
    assert sub.refresh_once()["status"] == "OK" and sub.search("finance")


def test_remote_rag_restart_reloads_verified_cache_and_rejects_tampered_or_expired(env):
    cache = env["tmp"] / "rag" / "evidence.json"
    env["refresher"].refresh_once()
    sub = env["subscriber"](cache); sub.refresh_once()
    restarted = env["subscriber"](cache)                            # no network needed to resume
    assert restarted.search("finance") and restarted.health()["seq"] == 1
    raw = json.loads(cache.read_bytes()); raw["chunks"][0]["content"] += " injected"
    cache.write_text(json.dumps(raw))
    tampered = env["subscriber"](cache)
    assert tampered.health()["state"] == "NO_EVIDENCE" and "CACHE_REJECTED" in tampered.health()["last_error"]
    with pytest.raises(EvidenceUnavailable):
        tampered.search("finance")
    env["refresher"].refresh_once(); env["subscriber"](cache).refresh_once()
    env["clock"].t += TTL + 1
    expired = env["subscriber"](cache)
    with pytest.raises(EvidenceUnavailable):
        expired.search("finance")


def test_cross_tenant_isolation(env):
    env["refresher"].refresh_once()
    m = env["pub"].read_current()
    for t, a, s in (("tenant-b", A, S), (T, "other-app", S), (T, A, "other-source")):
        with pytest.raises(ManifestError, match="BINDING_MISMATCH"):
            verify_manifest(m, manifest_keys={"manifest-1": env["mkey"].public_key()},
                            attestation_keys={"ingest-1": env["ingest"].public_key()}, tenant_id=t, application_id=a,
                            source_id=s, now=int(env["clock"]()))
    keys = {"ingest-1": env["ingest"].public_key()}
    assert env["dist"].serve(tenant_id="tenant-b", application_id=A, source_id=S, attestation_keys=keys)[0] == 404
    for bad in ("../tenant-b", "a/b", "", None, "x" * 200):
        assert env["dist"].serve(tenant_id=T, application_id=A, source_id=bad, attestation_keys=keys)[0] == 400
    # A tenant-B manifest planted in tenant A's directory is refused (signed binding).
    srcb = Source(env["ingest"], env["clock"], tenant="tenant-b")
    other = EvidenceRefresher(adapter=srcb, publisher=EvidencePublisher(env["tmp"] / "b", "tenant-b", A, S), tenant_id="tenant-b",
                              application_id=A, source_id=S, attestation_keys=keys, manifest_key=env["mkey"],
                              manifest_key_id="manifest-1", clock=env["clock"], sleep=lambda s: None)
    other.refresh_once()
    env["pub"].current.write_bytes(other.publisher.current.read_bytes())
    assert env["dist"].serve(tenant_id=T, application_id=A, source_id=S, attestation_keys=keys,
                             now=int(env["clock"]()))[1] == "MANIFEST_BINDING_MISMATCH"


def test_refresh_policy_bounds():
    with pytest.raises(ValueError):
        RefreshPolicy(interval_seconds=1800, attestation_ttl_seconds=1800)   # must refresh before expiry
    with pytest.raises(ValueError):
        RefreshPolicy(max_retries=50)


# ------------------------------------------------------------------ through the real Gateway + Guard
def test_gateway_serves_only_verified_evidence_and_it_never_bypasses_guard(tmp_path, monkeypatch):
    from tests.security import test_gateway_all_response_routes as routes
    from tests.security.test_gateway_remote_exposure import SECRET, _remote_env, _signed
    from tests.security.test_multisource_guard_v2 import _token
    from packages.rag_core.request_signing import signed_headers

    captured = []
    real = routes.Ed25519PrivateKey

    class Capture:
        @staticmethod
        def generate():
            k = real.generate(); captured.append(k); return k
        from_private_bytes = staticmethod(real.from_private_bytes)
    monkeypatch.setattr(routes, "Ed25519PrivateKey", Capture)
    _remote_env(monkeypatch)
    mkey = Ed25519PrivateKey.generate()
    dist = EvidenceDistribution(tmp_path / "pub", {"manifest-1": mkey.public_key()})
    real_create = routes.create_app
    monkeypatch.setattr(routes, "create_app", lambda *a, **k: real_create(*a, **{**k, "evidence": dist}))
    gateway, _p, observed, chunk, *_ = routes._gateway(tmp_path, monkeypatch)
    source_key = captured[0]
    signer = SourceAttestationSigner(key_id="source-trusted", private_key=source_key)
    pub = EvidencePublisher(tmp_path / "pub", "tenant-a", routes.APP, chunk.source_id)

    def adapter():
        att = signer.issue(ContentBinding(tenant_id="tenant-a", application_id=routes.APP, source_id=chunk.source_id,
                                          resource_id=chunk.resource_id, chunk_id=chunk.chunk_id,
                                          content_version=chunk.content_version, content=chunk.content), ttl_seconds=TTL)
        return {"documents": [{"resource_id": chunk.resource_id, "content_version": chunk.content_version}],
                "chunks": [{"resource_id": chunk.resource_id, "chunk_id": chunk.chunk_id, "content_version": chunk.content_version,
                            "content": chunk.content, "content_attestation": att}]}
    EvidenceRefresher(adapter=adapter, publisher=pub, tenant_id="tenant-a", application_id=routes.APP, source_id=chunk.source_id,
                      attestation_keys={"source-trusted": source_key.public_key()}, manifest_key=mkey,
                      manifest_key_id="manifest-1").refresh_once()
    body = json.dumps({"source_id": chunk.source_id}).encode()
    with gateway:
        unsigned = gateway.post("/v1/evidence/manifest", content=body)
        ok = gateway.post("/v1/evidence/manifest", content=body,
                          headers=signed_headers("rag-prod", SECRET, "POST", "/v1/evidence/manifest", body, ""))
        manifest = ok.json()
        assert ok.status_code == 200, ok.text
        c = manifest["chunks"][0]
        res = {"source_id": chunk.source_id, "resource_id": c["resource_id"], "chunk_id": c["chunk_id"], "content": c["content"],
               "content_version": c["content_version"], "content_attestation": c["content_attestation"]}
        ask = {"application_id": routes.APP, "employee_question": "What is available?", "retrieved_resources": [res], "stream": False}
        raw_a, h_a = _signed(ask, "alice"); raw_b, h_b = _signed(ask, "bob")
        alice = gateway.post("/v1/chat/completions", content=raw_a, headers=h_a)
        bob = gateway.post("/v1/chat/completions", content=raw_b, headers=h_b)
    assert unsigned.status_code == 401
    assert ok.status_code == 200 and manifest["seq"] == 1
    assert alice.status_code == 200
    assert bob.status_code in (403, 503) and observed["llm_count"] == 1      # fresh evidence grants Bob nothing
    _ = _token
