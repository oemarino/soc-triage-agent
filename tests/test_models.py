"""Schema tests for the T2 alert model."""

from __future__ import annotations

from typing import get_args

import pytest
from pydantic import ValidationError

from soc_triage.models import CATEGORIES, Alert, AlertCategory, Ioc, LabelSet, Severity


def _alert(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "SYN-BF-900",
        "timestamp": "2026-03-10T00:00:00Z",
        "source": "demo-auth-gateway",
        "category": "brute_force",
        "raw_fields": {"summary": "synthetic unit alert"},
    }
    base.update(overrides)
    return base


def test_category_constant_matches_literal() -> None:
    assert set(get_args(AlertCategory)) == set(CATEGORIES)
    assert len(CATEGORIES) >= 5


def test_minimal_alert_omits_iocs() -> None:
    alert = Alert.model_validate(_alert())
    assert alert.iocs == []
    assert alert.category == "brute_force"
    assert alert.timestamp.tzinfo is not None


def test_round_trip() -> None:
    alert = Alert.model_validate(_alert())
    again = Alert.model_validate(alert.model_dump(mode="json"))
    assert again == alert


def test_rejects_naive_timestamp() -> None:
    with pytest.raises(ValidationError):
        Alert.model_validate(_alert(timestamp="2026-03-10T00:00:00"))


def test_rejects_unknown_category_and_extra_field() -> None:
    with pytest.raises(ValidationError):
        Alert.model_validate(_alert(category="ransomware"))
    with pytest.raises(ValidationError):
        Alert.model_validate({**_alert(), "ticket": "INC-1"})


def test_sha256_ioc_must_be_hex() -> None:
    with pytest.raises(ValidationError):
        Ioc.model_validate({"type": "sha256", "value": "not-a-hash"})


def test_label_set_rejects_duplicate_ids() -> None:
    payload = {
        "version": 1,
        "dataset": "synthetic-soc-triage",
        "description": "synthetic unit labels",
        "provenance": "unit test",
        "labels": [
            {"id": "SYN-BF-001", "severity": "high"},
            {"id": "SYN-BF-001", "severity": "low"},
        ],
    }
    with pytest.raises(ValidationError):
        LabelSet.model_validate(payload)


def test_severity_values_match_plan() -> None:
    assert [level.value for level in Severity] == [
        "critical",
        "high",
        "medium",
        "low",
        "info",
    ]
