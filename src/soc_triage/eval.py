"""Compare predicted severity to labeled fixtures.

Offline only. No network and no API key. The bundled labels are a small
synthetic set the rules were tuned on. The score is not real-world accuracy.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from soc_triage.models import Alert, LabelSet, Reason, Severity
from soc_triage.rules import score_alert

SEVERITY_ORDER: tuple[Severity, ...] = tuple(Severity)

CAVEAT = (
    "The labeled set is small and synthetic. The rules were tuned on these "
    "same alerts, so this score is not a measure of real-world accuracy. "
    "A held-out split is future work (T9)."
)


class EvalError(ValueError):
    """Labels cannot be compared to the loaded alerts."""


class ClassMetrics(BaseModel):
    """Precision and recall for one severity on the labeled rows only."""

    model_config = ConfigDict(extra="forbid")

    severity: Severity
    labeled: int = Field(ge=0)
    predicted: int = Field(ge=0)
    true_positive: int = Field(ge=0)
    precision: float | None = None
    recall: float | None = None


class Mismatch(BaseModel):
    """One labeled alert whose rule severity differs from the label."""

    model_config = ConfigDict(extra="forbid")

    alert_id: str
    labeled: Severity
    predicted: Severity
    reasons: list[Reason] = Field(min_length=1)


class EvalReport(BaseModel):
    """Metrics for one labeled comparison. Unlabeled alerts are excluded."""

    model_config = ConfigDict(extra="forbid")

    banner: str = Field(min_length=1)
    caveat: str = Field(min_length=1)
    alert_count: int = Field(ge=0)
    labeled_count: int = Field(ge=0)
    exact_matches: int = Field(ge=0)
    accuracy: float | None = None
    per_severity: list[ClassMetrics]
    confusion_labels: list[str]
    confusion_matrix: list[list[int]]
    mismatches: list[Mismatch]


def evaluate(alerts: list[Alert], labels: LabelSet, *, banner: str) -> EvalReport:
    """Score labeled alerts with the rules engine and compare them to labels."""
    if not labels.labels:
        raise EvalError("Label file has no labels.")
    by_id = {alert.id: alert for alert in alerts}
    mismatches: list[Mismatch] = []
    pairs: list[tuple[Severity, Severity]] = []
    for label in labels.labels:
        alert = by_id.get(label.id)
        if alert is None:
            raise EvalError(f"Label {label.id} does not match a loaded alert.")
        result = score_alert(alert)
        pairs.append((label.severity, result.severity))
        if result.severity is not label.severity:
            mismatches.append(
                Mismatch(
                    alert_id=alert.id,
                    labeled=label.severity,
                    predicted=result.severity,
                    reasons=list(result.reasons),
                )
            )
    mismatches.sort(key=lambda item: item.alert_id)
    exact_matches = sum(1 for labeled, predicted in pairs if labeled is predicted)
    total = len(pairs)
    return EvalReport(
        banner=banner,
        caveat=CAVEAT,
        alert_count=len(alerts),
        labeled_count=total,
        exact_matches=exact_matches,
        accuracy=exact_matches / total,
        per_severity=class_metrics(pairs),
        confusion_labels=[level.value for level in SEVERITY_ORDER],
        confusion_matrix=confusion_matrix(pairs),
        mismatches=mismatches,
    )


def class_metrics(pairs: list[tuple[Severity, Severity]]) -> list[ClassMetrics]:
    """Per-severity counts, precision, and recall. ``None`` means no support."""
    metrics: list[ClassMetrics] = []
    for level in SEVERITY_ORDER:
        labeled = sum(1 for truth, _predicted in pairs if truth is level)
        predicted = sum(1 for _truth, guess in pairs if guess is level)
        true_positive = sum(
            1 for truth, guess in pairs if truth is level and guess is level
        )
        metrics.append(
            ClassMetrics(
                severity=level,
                labeled=labeled,
                predicted=predicted,
                true_positive=true_positive,
                precision=None if predicted == 0 else true_positive / predicted,
                recall=None if labeled == 0 else true_positive / labeled,
            )
        )
    return metrics


def confusion_matrix(pairs: list[tuple[Severity, Severity]]) -> list[list[int]]:
    """Rows are labeled severity. Columns are predicted severity."""
    index = {level: position for position, level in enumerate(SEVERITY_ORDER)}
    matrix = [[0 for _column in SEVERITY_ORDER] for _row in SEVERITY_ORDER]
    for labeled, predicted in pairs:
        matrix[index[labeled]][index[predicted]] += 1
    return matrix


def render_eval_markdown(report: EvalReport) -> str:
    """Human-readable metrics. The banner is the first line."""
    if report.accuracy is None:
        accuracy = "n/a (no labeled alerts)"
    else:
        accuracy = (
            f"{report.exact_matches}/{report.labeled_count} "
            f"({report.accuracy:.0%})"
        )
    lines = [
        report.banner,
        "",
        "# Eval summary",
        "",
        (
            f"Labeled alerts: {report.labeled_count} of {report.alert_count} "
            "loaded. Unlabeled alerts are excluded."
        ),
        f"Exact-match accuracy: {accuracy}.",
        "",
        report.caveat,
        "",
        "## Per severity",
        "",
        "Counts use only labeled alerts. Precision and recall are n/a when the denominator is 0.",
        "",
        "| Severity | Labeled | Predicted | TP | Precision | Recall |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in report.per_severity:
        lines.append(
            f"| {row.severity.value} | {row.labeled} | {row.predicted} | "
            f"{row.true_positive} | {_ratio(row.precision)} | {_ratio(row.recall)} |"
        )
    lines.extend(
        [
            "",
            "## Confusion matrix",
            "",
            "Rows are labeled severity. Columns are predicted severity.",
            "",
            _matrix_header(),
            "| --- | " + " | ".join("---" for _level in SEVERITY_ORDER) + " |",
        ]
    )
    for label, row in zip(report.confusion_labels, report.confusion_matrix, strict=True):
        cells = " | ".join(str(count) for count in row)
        lines.append(f"| {label} | {cells} |")
    lines.extend(["", "## Mismatches", ""])
    if not report.mismatches:
        lines.append("No mismatches.")
    else:
        for mismatch in report.mismatches:
            lines.append(
                f"- {mismatch.alert_id}: labeled {mismatch.labeled.value}, "
                f"predicted {mismatch.predicted.value}"
            )
            for reason in mismatch.reasons:
                lines.append(f"  - ({reason.code}) {reason.message}")
    lines.append("")
    return "\n".join(lines)


def render_eval_json(report: EvalReport) -> str:
    """Full metrics, including the caveat and any mismatches."""
    return report.model_dump_json(indent=2) + "\n"


def _ratio(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.2f}"


def _matrix_header() -> str:
    columns = " | ".join(level.value for level in SEVERITY_ORDER)
    return f"| Labeled \\ Predicted | {columns} |"
