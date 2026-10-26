from packages.connector_sdk.target import TargetObservation
from packages.domain.models import EvidenceLevel
from packages.test_engine.oracle import detect_exposure


def test_oracle_uses_deterministic_signals():
    m = detect_exposure(
        TargetObservation(available=True, answer="hello AP-CANARY-ABC"),
        canary="AP-CANARY-ABC",
        resource_id="r1",
    )
    assert m.exposed and m.level is EvidenceLevel.ANSWER


def test_oracle_citation_level():
    m = detect_exposure(
        TargetObservation(available=True, citations=["r1"]),
        canary="AP-CANARY-ABC",
        resource_id="r1",
    )
    assert m.exposed and m.level is EvidenceLevel.CITATION


def test_detects_numeric_paraphrase_of_protected_fact():
    m = detect_exposure(
        TargetObservation(available=True, answer="Project Phoenix acquisition came in around 847.4m."),
        canary="AP-CANARY-hidden",
        resource_id="resource-1",
        protected_signals=["Project Phoenix acquisition value is 847391271.", "847391271"],
    )
    assert m.exposed is True
    assert m.level is EvidenceLevel.ANSWER
