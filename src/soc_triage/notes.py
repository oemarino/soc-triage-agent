"""Draft analyst notes from rule output.

TODO(T7): optional OpenAI-compatible enrichment, gated by environment
variables, falling back to this template when no key is set.
Notes never decide severity.
"""

from __future__ import annotations

from soc_triage.models import Alert, TriageResult

TODO = "T7"


def draft_note(alert: Alert, result: TriageResult) -> str:
    """Template note. No network call and no API key.

    The text cites rule reasons and alert fields. It repeats the rule
    severity and does not choose a different one.
    """
    summary = alert.raw_fields.get("summary")
    if isinstance(summary, str) and summary.strip():
        observation = summary.strip()
    else:
        observation = "raw_fields.summary is absent"
    review = (
        "Needs human review before anyone acts."
        if result.needs_review
        else "Signals agree; a human still confirms before anyone acts."
    )
    reason_lines = "\n".join(
        f"- ({reason.code}) {reason.message}" for reason in result.reasons
    )
    return (
        f"Draft for {alert.id} from {alert.source} at {alert.timestamp.isoformat()}. "
        f"Category {alert.category}. Recommended severity {result.severity.value} "
        f"with confidence {result.confidence:.2f}. {review} "
        "This note does not change the rule severity.\n"
        f"Observation: {observation}\n"
        f"Cited fields: {_cited_fields(alert)}\n"
        f"Rule reasons:\n{reason_lines}"
    )


def _cited_fields(alert: Alert) -> str:
    parts: list[str] = []
    for key, value in alert.raw_fields.items():
        if key == "summary":
            continue
        if isinstance(value, bool):
            rendered = "true" if value else "false"
        elif isinstance(value, (str, int, float)):
            rendered = str(value)
        else:
            continue
        parts.append(f"raw_fields.{key}={rendered}")
    if not parts:
        return "no additional raw fields"
    return ", ".join(parts)
