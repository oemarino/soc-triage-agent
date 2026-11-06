"""Metric math and CLI tests for the eval harness."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from soc_triage.cli import app, safety_banner
from soc_triage.eval import (
    CAVEAT,
    EvalError,
    class_metrics,
    confusion_matrix,
    evaluate,
    render_eval_markdown,
)
from soc_triage.ingest import default_alerts_dir, default_labels_path, load_alerts, load_labels
from soc_triage.models import Label, LabelSet, Severity
from soc_triage.rules import score_alert

ROOT = Path(__file__).resolve().parents[1]
RUNNER = CliRunner()


def test_precision_recall_and_confusion_math() -> None:
    pairs = [
        (Severity.CRITICAL, Severity.CRITICAL),
        (Severity.CRITICAL, Severity.HIGH),
        (Severity.HIGH, Severity.HIGH),
    ]
    metrics = {row.severity: row for row in class_metrics(pairs)}
    assert metrics[Severity.CRITICAL].labeled == 2
    assert metrics[Severity.CRITICAL].predicted == 1
    assert metrics[Severity.CRITICAL].true_positive == 1
    assert metrics[Severity.CRITICAL].precision == 1.0
    assert metrics[Severity.CRITICAL].recall == 0.5
    assert metrics[Severity.HIGH].precision == 0.5
    assert metrics[Severity.HIGH].recall == 1.0
    assert metrics[Severity.MEDIUM].precision is None
    assert metrics[Severity.MEDIUM].recall is None
    assert metrics[Severity.INFO].labeled == 0

    matrix = confusion_matrix(pairs)
    labels = list(Severity)
    critical = labels.index(Severity.CRITICAL)
    high = labels.index(Severity.HIGH)
    assert matrix[critical][critical] == 1
    assert matrix[critical][high] == 1
    assert matrix[high][high] == 1
    assert sum(sum(row) for row in matrix) == 3


def test_empty_support_has_no_precision_or_recall() -> None:
    forced = class_metrics([])
    assert len(forced) == len(list(Severity))
    assert all(row.labeled == 0 and row.predicted == 0 for row in forced)
    assert all(row.precision is None and row.recall is None for row in forced)


def test_bundled_labels_are_small_and_caveated() -> None:
    alerts = load_alerts(default_alerts_dir())
    labels = load_labels(default_labels_path())
    report = evaluate(alerts, labels, banner=safety_banner())
    assert report.labeled_count == 15
    assert report.alert_count == 25
    assert report.labeled_count < report.alert_count
    manual = 0
    by_id = {alert.id: alert for alert in alerts}
    for label in labels.labels:
        predicted = score_alert(by_id[label.id]).severity
        manual += int(predicted is label.severity)
    assert report.exact_matches == manual == 15
    assert report.accuracy == 1.0
    assert report.mismatches == []
    assert "not a measure of real-world accuracy" in report.caveat
    assert "synthetic" in report.caveat
    assert "tuned" in report.caveat
    assert "T9" in report.caveat
    assert report.caveat == CAVEAT
    diagonal = sum(
        report.confusion_matrix[index][index] for index in range(len(report.confusion_labels))
    )
    assert diagonal == report.exact_matches


def test_mismatch_lists_id_and_reasons() -> None:
    alerts = [alert for alert in load_alerts(default_alerts_dir()) if alert.id == "SYN-BF-001"]
    labels = LabelSet(
        version=1,
        dataset="synthetic-unit",
        description="synthetic mismatch case",
        provenance="unit test",
        labels=[Label(id="SYN-BF-001", severity=Severity.HIGH)],
    )
    report = evaluate(alerts, labels, banner=safety_banner())
    assert report.accuracy == 0.0
    assert len(report.mismatches) == 1
    mismatch = report.mismatches[0]
    assert mismatch.alert_id == "SYN-BF-001"
    assert mismatch.labeled is Severity.HIGH
    assert mismatch.predicted is Severity.CRITICAL
    assert mismatch.reasons
    text = render_eval_markdown(report)
    assert "SYN-BF-001: labeled high, predicted critical" in text
    assert mismatch.reasons[0].message in text
    assert "n/a" in text


def test_missing_alert_and_empty_labels_fail() -> None:
    alerts = load_alerts(default_alerts_dir())
    missing = LabelSet(
        version=1,
        dataset="synthetic-unit",
        description="synthetic missing id",
        provenance="unit test",
        labels=[Label(id="SYN-MISSING-1", severity=Severity.LOW)],
    )
    try:
        evaluate(alerts, missing, banner=safety_banner())
    except EvalError as exc:
        assert "SYN-MISSING-1" in str(exc)
    else:
        raise AssertionError("expected EvalError")

    empty = LabelSet(
        version=1,
        dataset="synthetic-unit",
        description="synthetic empty labels",
        provenance="unit test",
        labels=[],
    )
    try:
        evaluate(alerts, empty, banner=safety_banner())
    except EvalError as exc:
        assert "no labels" in str(exc).lower()
    else:
        raise AssertionError("expected EvalError")


def test_eval_cli_reports_bundled_metrics(tmp_path: Path) -> None:
    destination = tmp_path / "metrics.json"
    result = CliRunner().invoke(
        app,
        [
            "eval",
            "--alerts",
            str(default_alerts_dir()),
            "--labels",
            str(default_labels_path()),
            "--json",
            str(destination),
        ],
    )
    assert result.exit_code == 0, result.stderr
    assert result.stdout.startswith(safety_banner())
    assert "Exact-match accuracy: 15/15 (100%)." in result.stdout
    assert "Labeled alerts: 15 of 25 loaded." in result.stdout
    assert "not a measure of real-world accuracy" in result.stdout
    assert "T9" in result.stdout
    assert "Rows are labeled severity. Columns are predicted severity." in result.stdout
    assert "No mismatches." in result.stdout
    assert "| critical | 4 | 0 | 0 | 0 | 0 |" in result.stdout

    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["labeled_count"] == 15
    assert payload["accuracy"] == 1.0
    assert payload["mismatches"] == []
    assert "T9" in payload["caveat"]


def test_eval_cli_default_paths_and_bad_labels(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["eval"])
    assert result.exit_code == 0, result.stderr
    assert "15/15" in result.stdout

    missing = CliRunner().invoke(app, ["eval", "--labels", str(tmp_path / "missing.json")])
    assert missing.exit_code == 1
    assert "not found" in missing.stderr.lower() or "Label file not found" in missing.stderr
