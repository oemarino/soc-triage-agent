"""Draft analyst notes from rule output.

``draft_note`` is the template. It cites rule reasons and alert fields
and repeats the rule severity. ``resolve_note`` may replace that text
with a configured model rewrite. The model cannot change severity,
confidence, needs_review, or reasons. Any failure keeps the template.
"""

from __future__ import annotations

from typing import Literal, NamedTuple, Protocol

from soc_triage.llm import LlmNoteError, validate_llm_note
from soc_triage.models import Alert, TriageResult

NoteSource = Literal["rules", "llm"]


class NoteRewriter(Protocol):
    """Something that returns replacement note text or raises ``LlmNoteError``."""

    def rewrite(self, alert: Alert, result: TriageResult) -> str:
        """Return untrusted note text."""


class ResolvedNote(NamedTuple):
    """Note text, where it came from, and a short fallback reason when kept."""

    text: str
    source: NoteSource
    fallback_reason: str | None


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


def resolve_note(
    alert: Alert,
    result: TriageResult,
    rewriter: NoteRewriter | None = None,
) -> ResolvedNote:
    """Use the template, or a validated rewrite that does not touch the score.

    ``rewriter`` is None unless the caller explicitly enabled LLM notes.
    Timeout, transport errors, and invalid text fall back to the template.
    """
    template = draft_note(alert, result)
    if rewriter is None:
        return ResolvedNote(template, "rules", None)
    try:
        text = validate_llm_note(rewriter.rewrite(alert, result))
    except LlmNoteError as exc:
        reason = str(exc).strip() or "request failed"
        return ResolvedNote(template, "rules", reason)
    except Exception:
        return ResolvedNote(template, "rules", "request failed")
    return ResolvedNote(text, "llm", None)


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
