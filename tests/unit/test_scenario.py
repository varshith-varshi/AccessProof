import pytest
from pydantic import ValidationError
from packages.domain.scenario import ScenarioDefinition


def test_timeout_must_exceed_slo():
    with pytest.raises(ValidationError):
        ScenarioDefinition(name="abc", maximum_slo_seconds=60, timeout_seconds=30)
