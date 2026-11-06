"""Render a ranked triage list.

Markdown for a human reader and JSON for a later eval or download.
Severity order follows plan.md: critical, high, medium, low, info.
Within a severity, higher confidence ranks first. Alert id breaks ties.
"""

from __future__ import annotations

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from soc_triage.models import Alert, Reason, Severity
from soc_triage.notes import draft_note
from soc_triage.rules import score_alert

SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


class RankedAlert(BaseModel):
    """One scored alert in display order, plus a template note."""

    model_config = ConfigDict(extra="forbid")

    id: str
    category: str
    source: str
    timestamp: AwareDatetime
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    needs_review: bool
    reasons: list[Reason] = Field(min_length=1)
    note: str = Field(min_length=1)


class TriageReport(BaseModel):
    """Full ranked run. ``banner`` states synthetic/demo mode."""

    model_config = ConfigDict(extra="forbid")

    banner: str = Field(min_length=1)
    mode: str = "synthetic"
    count: int = Field(ge=0)
    results: list[RankedAlert]


def build_report(alerts: list[Alert], *, banner: str) -> TriageReport:
    """Score every alert, draft a template note, and rank the rows."""
    rows: list[RankedAlert] = []
    for alert in alerts:
        result = score_alert(alert)
        rows.append(
            RankedAlert(
                id=alert.id,
                category=alert.category,
                source=alert.source,
                timestamp=alert.timestamp,
                severity=result.severity,
                confidence=result.confidence,
                needs_review=result.needs_review,
                reasons=list(result.reasons),
                note=draft_note(alert, result),
            )
        )
    return TriageReport(banner=banner, count=len(rows), results=order_results(rows))


def order_results(results: list[RankedAlert]) -> list[RankedAlert]:
    """Rank by severity, then confidence descending, then id."""
    return sorted(
        results,
        key=lambda row: (SEVERITY_ORDER.index(row.severity), -row.confidence, row.id),
    )


def render_markdown(report: TriageReport) -> str:
    """Human-readable summary. The banner is the first line."""
    lines = [
        report.banner,
        "",
        f"# Triage summary ({report.count} alerts)",
        "",
        _count_line(report.results),
        "",
        "Ranked by severity, then confidence. Recommendations only; a human makes the final call.",
        "",
        "| Rank | Id | Category | Severity | Confidence | Needs review | Top reasons |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for index, row in enumerate(report.results, start=1):
        review = "yes" if row.needs_review else "no"
        lines.append(
            f"| {index} | {row.id} | {row.category} | {row.severity.value} | "
            f"{row.confidence:.2f} | {review} | {_top_reasons(row)} |"
        )
    lines.extend(["", "## Draft notes", ""])
    for row in report.results:
        lines.append(f"### {row.id}")
        lines.append("")
        lines.append(row.note)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_json(report: TriageReport) -> str:
    """Full ranked results, including reasons and draft notes."""
    return report.model_dump_json(indent=2) + "\n"


def _count_line(results: list[RankedAlert]) -> str:
    parts = [
        f"{sum(1 for row in results if row.severity is level)} {level.value}"
        for level in SEVERITY_ORDER
    ]
    return " · ".join(parts)


def _top_reasons(row: RankedAlert, limit: int = 2) -> str:
    preferred = [reason for reason in row.reasons if reason.code != "category_baseline"]
    baseline = [reason for reason in row.reasons if reason.code == "category_baseline"]
    chosen = (preferred + baseline)[:limit]
    if not chosen:
        return "none"
    return " · ".join(_cell(reason.message) for reason in chosen)


def _cell(text: str, limit: int = 72) -> str:
    cleaned = " ".join(text.split()).replace("|", "/")
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 3] + "..."
