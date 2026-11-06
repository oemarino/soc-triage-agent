"""Rendering and ranking tests for the T4 triage report."""

from __future__ import annotations

import json
from pathlib import Path

from soc_triage.cli import safety_banner
from soc_triage.ingest import load_alerts
from soc_triage.models import Reason, Severity
from soc_triage.notes import draft_note
from soc_triage.report import RankedAlert, build_report, order_results, render_json, render_markdown
from soc_triage.rules import score_alert

ROOT = Path(__file__).resolve().parents[1]
ALERTS = ROOT / "fixtures" / "alerts"


def _row(alert_id: str, severity: Severity, confidence: float) -> RankedAlert:
    return RankedAlert(
        id=alert_id,
        category="policy_noise",
        source="demo-policy-monitor",
        timestamp="2026-03-10T00:00:00Z",
        severity=severity,
        confidence=confidence,
        needs_review=False,
        reasons=[
            Reason(code="category_baseline", message="category policy_noise baseline is info")
        ],
        note="Draft note for the rank test.",
    )


def test_order_is_severity_then_confidence_then_id() -> None:
    ordered = order_results(
        [
            _row("SYN-PN-003", Severity.HIGH, 0.50),
            _row("SYN-PN-001", Severity.CRITICAL, 0.90),
            _row("SYN-PN-002", Severity.HIGH, 0.95),
            _row("SYN-PN-004", Severity.INFO, 0.99),
        ]
    )
    assert [row.id for row in ordered] == [
        "SYN-PN-001",
        "SYN-PN-002",
        "SYN-PN-003",
        "SYN-PN-004",
    ]


def test_fixture_report_ranks_critical_before_info() -> None:
    report = build_report(load_alerts(ALERTS), banner=safety_banner())
    assert report.count == 25
    assert report.results[0].id == "SYN-BF-001"
    assert report.results[0].severity is Severity.CRITICAL
    assert report.results[-1].severity is Severity.INFO
    ids = [row.id for row in report.results]
    assert ids.index("SYN-BF-001") < ids.index("SYN-PN-005")
    rank = {
        level: index
        for index, level in enumerate(
            (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
        )
    }
    severities = [row.severity for row in report.results]
    assert all(rank[left] <= rank[right] for left, right in zip(severities, severities[1:]))


def test_markdown_summary_lists_required_columns() -> None:
    report = build_report(load_alerts(ALERTS / "brute_force.json"), banner=safety_banner())
    text = render_markdown(report)
    assert text.startswith(safety_banner())
    assert "| Rank | Id | Category | Severity | Confidence | Needs review | Top reasons |" in text
    first = report.results[0]
    assert first.id in text
    assert first.category in text
    assert first.severity.value in text
    assert "yes" in text or "no" in text
    assert "## Draft notes" in text
    assert "Recommended severity" in text
    assert "1 critical" in text
    assert "AI-drafted, analyst review required." not in text


def test_markdown_counts_and_top_reasons() -> None:
    report = build_report(load_alerts(ALERTS), banner=safety_banner())
    text = render_markdown(report)
    assert "4 critical · 4 high · 5 medium · 5 low · 7 info" in text
    assert "failure_count=86" in text or "success_after_failures=true" in text


def test_json_contains_full_ranked_results() -> None:
    report = build_report(load_alerts(ALERTS / "brute_force.json"), banner=safety_banner())
    payload = json.loads(render_json(report))
    assert payload["banner"] == safety_banner()
    assert payload["mode"] == "synthetic"
    assert payload["count"] == 5
    first = payload["results"][0]
    assert first["id"] == "SYN-BF-001"
    assert first["severity"] == "critical"
    assert first["needs_review"] is False
    assert first["reasons"]
    assert first["note_source"] == "rules"
    assert "Recommended severity critical" in first["note"]


def test_template_note_cites_rules_and_fields() -> None:
    alert = next(item for item in load_alerts(ALERTS) if item.id == "SYN-BF-001")
    result = score_alert(alert)
    note = draft_note(alert, result)
    assert f"Recommended severity {result.severity.value}" in note
    assert "raw_fields.failure_count=86" in note
    assert result.reasons[0].message in note
    assert "This note does not change the rule severity." in note
