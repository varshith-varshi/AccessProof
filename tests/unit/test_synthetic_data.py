from packages.domain.scenario import ScenarioDefinition
from packages.test_engine.synthetic import (
    deterministic_probes,
    generate_synthetic_document,
    synthetic_categories,
)


def test_synthetic_templates_cover_multiple_enterprise_domains_and_stay_unique():
    expected = {
        "finance",
        "hr",
        "legal",
        "m_and_a",
        "engineering",
        "sales",
        "customer_support",
        "procurement",
        "project_planning",
    }
    assert expected.issubset(set(synthetic_categories()))
    docs = [generate_synthetic_document(category=name) for name in sorted(expected)]
    assert len({doc.canary for doc in docs}) == len(docs)
    assert len({doc.fingerprint for doc in docs}) == len(docs)
    assert all(doc.canary in doc.body for doc in docs)
    assert all("Distractor:" in doc.body for doc in docs)


def test_deterministic_probes_follow_the_actual_synthetic_subject_and_fact_family():
    doc = generate_synthetic_document(category="engineering")
    probes = deterministic_probes(doc)
    assert len(probes) >= 5
    assert all(doc.subject in probe for probe in probes)
    assert any(doc.secret_label in probe for probe in probes)


def test_scenario_can_select_synthetic_domain():
    scenario = ScenarioDefinition(
        name="HR group revoke", synthetic_category="hr", maximum_slo_seconds=30, timeout_seconds=120
    )
    assert scenario.synthetic_category.value == "hr"
