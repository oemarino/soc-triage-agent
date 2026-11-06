"""Unit tests for each rules-engine family and the bundled fixtures."""

from __future__ import annotations

from soc_triage.ingest import default_alerts_dir, default_labels_path, load_alerts, load_labels
from soc_triage.models import Alert, Severity, TriageResult
from soc_triage.rules import score_alert

# Rules output for every bundled alert, including ids that labels.json omits.
# Labeled rows match fixtures/labels.json. There are no intentional mismatches.
EXPECTED_SEVERITY = {
    "SYN-BF-001": "critical",
    "SYN-BF-002": "high",
    "SYN-BF-003": "medium",
    "SYN-BF-004": "low",
    "SYN-BF-005": "info",
    "SYN-PH-001": "critical",
    "SYN-PH-002": "high",
    "SYN-PH-003": "medium",
    "SYN-PH-004": "low",
    "SYN-PH-005": "info",
    "SYN-MH-001": "critical",
    "SYN-MH-002": "high",
    "SYN-MH-003": "medium",
    "SYN-MH-004": "low",
    "SYN-MH-005": "info",
    "SYN-LM-001": "critical",
    "SYN-LM-002": "high",
    "SYN-LM-003": "medium",
    "SYN-LM-004": "low",
    "SYN-LM-005": "info",
    "SYN-PN-001": "info",
    "SYN-PN-002": "info",
    "SYN-PN-003": "low",
    "SYN-PN-004": "medium",
    "SYN-PN-005": "info",
}

_SOURCES = {
    "brute_force": "demo-auth-gateway",
    "phishing_url": "demo-email-gateway",
    "malware_hash": "demo-edr",
    "lateral_movement": "demo-ndr",
    "policy_noise": "demo-policy-monitor",
}


def _alert(
    category: str,
    raw: dict[str, object] | None = None,
    iocs: list[dict[str, str]] | None = None,
    alert_id: str = "SYN-UNIT-1",
) -> Alert:
    fields: dict[str, object] = {
        "context_complete": True,
        "allowlisted": False,
        "summary": "synthetic unit alert",
    }
    if raw:
        fields.update(raw)
    payload: dict[str, object] = {
        "id": alert_id,
        "timestamp": "2026-03-10T00:00:00Z",
        "source": _SOURCES[category],
        "category": category,
        "raw_fields": fields,
    }
    if iocs is not None:
        payload["iocs"] = iocs
    return Alert.model_validate(payload)


def _codes(result: TriageResult) -> set[str]:
    return {reason.code for reason in result.reasons}


def test_category_baselines() -> None:
    policy = score_alert(_alert("policy_noise", {"event_count": 1}))
    assert policy.severity is Severity.INFO
    assert any(
        reason.code == "category_baseline" and "policy_noise" in reason.message
        for reason in policy.reasons
    )

    brute = score_alert(_alert("brute_force", {"failure_count": 12}))
    assert brute.severity is Severity.MEDIUM
    assert any("brute_force baseline is medium" in reason.message for reason in brute.reasons)

    phishing = score_alert(
        _alert(
            "phishing_url",
            {"url": "https://benefits.example/enroll", "clicked": False, "delivered": False},
            [{"type": "url", "value": "https://benefits.example/enroll", "reputation": "suspicious"}],
        )
    )
    assert phishing.severity is Severity.MEDIUM

    malware = score_alert(
        _alert(
            "malware_hash",
            {"sha256": "c" * 64, "executed": False, "quarantined": False},
            [{"type": "sha256", "value": "c" * 64, "reputation": "unknown"}],
        )
    )
    assert malware.severity is Severity.MEDIUM

    lateral = score_alert(_alert("lateral_movement", {"dest_host_count": 1, "remote_logon_count": 1}))
    assert lateral.severity is Severity.MEDIUM


def test_burst_thresholds_raise_brute_force_and_lateral() -> None:
    low = score_alert(_alert("brute_force", {"failure_count": 4, "success_after_failures": False}))
    medium = score_alert(_alert("brute_force", {"failure_count": 12, "success_after_failures": False}))
    high = score_alert(_alert("brute_force", {"failure_count": 42, "success_after_failures": False}))
    critical = score_alert(_alert("brute_force", {"failure_count": 86, "success_after_failures": True}))
    assert [item.severity for item in (low, medium, high, critical)] == [
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]
    assert "burst" in _codes(high)
    assert any("failure_count=42" in reason.message for reason in high.reasons)

    single = score_alert(_alert("lateral_movement", {"dest_host_count": 1}))
    spread = score_alert(_alert("lateral_movement", {"dest_host_count": 6, "admin_share_connections": 6}))
    assert single.severity is Severity.MEDIUM
    assert spread.severity is Severity.HIGH
    assert any("dest_host_count=6" in reason.message for reason in spread.reasons)


def test_ioc_reputation_changes_severity() -> None:
    unknown = score_alert(
        _alert(
            "malware_hash",
            {"sha256": "c" * 64, "executed": False, "quarantined": False},
            [{"type": "sha256", "value": "c" * 64, "reputation": "unknown"}],
        )
    )
    malicious = score_alert(
        _alert(
            "malware_hash",
            {"sha256": "b" * 64, "executed": False, "quarantined": True},
            [{"type": "sha256", "value": "b" * 64, "reputation": "malicious"}],
        )
    )
    executed = score_alert(
        _alert(
            "malware_hash",
            {"sha256": "a" * 64, "executed": True, "quarantined": False},
            [{"type": "sha256", "value": "a" * 64, "reputation": "malicious"}],
        )
    )
    assert unknown.severity is Severity.MEDIUM
    assert malicious.severity is Severity.HIGH
    assert executed.severity is Severity.CRITICAL
    assert "ioc_reputation" in _codes(executed)
    assert any("reputation=malicious" in reason.message for reason in executed.reasons)

    clicked = score_alert(
        _alert(
            "phishing_url",
            {"url": "https://sso.login.example/reset", "clicked": True, "delivered": True},
            [{"type": "url", "value": "https://sso.login.example/reset", "reputation": "malicious"}],
        )
    )
    delivered = score_alert(
        _alert(
            "phishing_url",
            {"url": "https://payroll.example/update", "clicked": False, "delivered": True},
            [{"type": "url", "value": "https://payroll.example/update", "reputation": "malicious"}],
        )
    )
    assert clicked.severity is Severity.CRITICAL
    assert delivered.severity is Severity.HIGH


def test_allowlist_downgrades_expected_activity() -> None:
    noisy = score_alert(
        _alert(
            "brute_force",
            {
                "failure_count": 86,
                "success_after_failures": True,
                "allowlisted": True,
                "allowlist_name": "vuln-scanner-demo",
            },
            [{"type": "ipv4", "value": "192.0.2.8", "reputation": "allowlisted"}],
        )
    )
    assert noisy.severity is Severity.INFO
    assert noisy.needs_review is False
    assert any(
        reason.code == "allowlist" and "vuln-scanner-demo" in reason.message
        for reason in noisy.reasons
    )

    bulk = score_alert(
        _alert(
            "policy_noise",
            {"event_count": 200, "allowlisted": True, "allowlist_name": "password-expiry-notices"},
        )
    )
    assert bulk.severity is Severity.INFO
    assert any("event_count=200" in reason.message for reason in bulk.reasons)
    assert "allowlist" in _codes(bulk)


def test_allowlist_conflict_is_not_critical() -> None:
    conflict = score_alert(
        _alert(
            "phishing_url",
            {
                "url": "https://sso.login.example/reset",
                "clicked": True,
                "delivered": True,
                "allowlisted": True,
                "allowlist_name": "awareness-drill",
            },
            [{"type": "url", "value": "https://sso.login.example/reset", "reputation": "malicious"}],
        )
    )
    assert conflict.severity is not Severity.CRITICAL
    assert conflict.severity is Severity.MEDIUM
    assert conflict.needs_review is True
    assert conflict.confidence < 0.5
    assert "allowlist" in _codes(conflict)


def test_incomplete_context_blocks_critical() -> None:
    capped = score_alert(
        _alert(
            "brute_force",
            {"failure_count": 86, "success_after_failures": True, "context_complete": False},
            [{"type": "ipv4", "value": "203.0.113.10", "reputation": "suspicious"}],
        )
    )
    assert capped.severity is Severity.LOW
    assert capped.needs_review is True
    assert capped.confidence < 0.5
    assert "incomplete_context" in _codes(capped)
    assert any("context_complete=false" in reason.message for reason in capped.reasons)


def test_missing_fields_fail_closed() -> None:
    missing_count = score_alert(_alert("brute_force", {}))
    assert missing_count.severity is Severity.LOW
    assert missing_count.needs_review is True
    assert any(reason.code == "missing_field" for reason in missing_count.reasons)

    missing_url = score_alert(_alert("phishing_url", {"clicked": True}))
    assert missing_url.severity is Severity.LOW
    assert missing_url.needs_review is True

    missing_hash = score_alert(_alert("malware_hash", {"executed": True}))
    assert missing_hash.severity is Severity.LOW
    assert missing_hash.needs_review is True

    missing_spread = score_alert(_alert("lateral_movement", {}))
    assert missing_spread.severity is Severity.LOW
    assert missing_spread.needs_review is True


def test_score_is_deterministic_and_cites_fields() -> None:
    alert = _alert(
        "lateral_movement",
        {"dest_host_count": 14, "remote_service_count": 14, "account_new": True, "off_hours": True},
        [{"type": "ipv4", "value": "203.0.113.50", "reputation": "malicious"}],
    )
    first = score_alert(alert)
    second = score_alert(alert)
    assert first == second
    assert first.severity is Severity.CRITICAL
    blob = " ".join(reason.message for reason in first.reasons)
    assert "dest_host_count=14" in blob
    assert "203.0.113.50" in blob
    assert "lateral_movement" in blob


def test_known_fixtures_match_expected_severities() -> None:
    alerts = load_alerts(default_alerts_dir())
    assert {alert.id for alert in alerts} == set(EXPECTED_SEVERITY)
    mismatches: list[str] = []
    for alert in alerts:
        result = score_alert(alert)
        expected = EXPECTED_SEVERITY[alert.id]
        if result.severity.value != expected:
            mismatches.append(f"{alert.id}: rules={result.severity.value} expected={expected}")
        assert result.alert_id == alert.id
        assert result.reasons
        assert result.severity.value in {"critical", "high", "medium", "low", "info"}
    assert mismatches == []


def test_labeled_fixtures_have_no_intentional_mismatches() -> None:
    alerts = {alert.id: alert for alert in load_alerts(default_alerts_dir())}
    labels = load_labels(default_labels_path())
    mismatches: list[str] = []
    for label in labels.labels:
        predicted = score_alert(alerts[label.id]).severity
        if predicted is not label.severity:
            mismatches.append(
                f"{label.id}: rules={predicted.value} label={label.severity.value}"
            )
    assert mismatches == []
    assert len(labels.labels) < len(alerts)


def test_clear_fixture_scores_do_not_need_review() -> None:
    alerts = {alert.id: alert for alert in load_alerts(default_alerts_dir())}
    decisive = score_alert(alerts["SYN-BF-001"])
    assert decisive.severity is Severity.CRITICAL
    assert decisive.needs_review is False
    assert decisive.confidence >= 0.8

    incomplete = score_alert(alerts["SYN-PN-003"])
    assert incomplete.severity is Severity.LOW
    assert incomplete.needs_review is True
