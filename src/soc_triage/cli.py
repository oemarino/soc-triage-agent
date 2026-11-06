"""Command-line interface.

`run` triages a fixture file or directory with the rules path.
`eval` compares those scores to a label file.
Every real run states synthetic/demo mode. No API key required.
`--llm-notes` is off by default and is the only path that can call a model.
"""

from __future__ import annotations

from pathlib import Path

import typer

from soc_triage.eval import EvalError, evaluate, render_eval_json, render_eval_markdown
from soc_triage.ingest import (
    FixtureLoadError,
    default_alerts_dir,
    default_labels_path,
    load_alerts,
    load_labels,
)
from soc_triage.llm import OpenAICompatibleClient, config_warning, load_llm_settings
from soc_triage.report import build_report, render_json, render_markdown

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=(
        "First-pass triage for synthetic SOC alerts. "
        "Demo and practice only — not a production SIEM."
    ),
)

SAFETY_BANNER = (
    "Synthetic/demo mode. This tool recommends severity and drafts notes; "
    "a human makes the final call. No auto-close, auto-block, or external notify."
)

_FORMATS = {"markdown", "json"}


def safety_banner() -> str:
    """Banner required on every triage run (spec: safety banner)."""
    return SAFETY_BANNER


def _note_rewriter(llm_notes: bool) -> OpenAICompatibleClient | None:
    """Build a client only when the flag and provider config both allow it."""
    if not llm_notes:
        return None
    settings = load_llm_settings()
    warning = config_warning(settings)
    if warning is not None:
        typer.echo(warning, err=True)
        return None
    typer.echo(
        "Sending structured alert fields and rule reasons to the configured model. "
        "Synthetic data only. Severity stays with the rules.",
        err=True,
    )
    return OpenAICompatibleClient(settings)


def _warn_note_fallback(alert_id: str, reason: str) -> None:
    typer.echo(
        f"LLM note for {alert_id} was not used ({reason}). Using the rule-based note.",
        err=True,
    )


@app.callback()
def main() -> None:
    """Portfolio SOC triage assistant. Synthetic data only."""


@app.command("run")
def run_command(
    path: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=True,
        readable=True,
        help="JSON alert file or directory of JSON alerts.",
    ),
    json_path: Path | None = typer.Option(
        None,
        "--json",
        help="Write the full ranked results to this JSON file.",
    ),
    output_format: str = typer.Option(
        "markdown",
        "--format",
        help="Stdout format: markdown or json.",
    ),
    llm_notes: bool = typer.Option(
        False,
        "--llm-notes",
        help=(
            "Rewrite each draft note with the configured OpenAI-compatible model. "
            "Off by default. Rules still set severity, confidence, needs_review, and reasons. "
            "Missing config, timeout, or invalid text keeps the template note."
        ),
    ),
) -> None:
    """Rank fixture alerts with the rules engine. No API key required.

    Pass --llm-notes to rewrite note text only, and only when provider config is set.
    """
    chosen = output_format.lower()
    if chosen not in _FORMATS:
        typer.echo("Unknown format. Use markdown or json.", err=True)
        raise typer.Exit(code=2)

    try:
        alerts = load_alerts(path)
    except FixtureLoadError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    rewriter = _note_rewriter(llm_notes)
    report = build_report(
        alerts,
        banner=safety_banner(),
        rewriter=rewriter,
        on_fallback=_warn_note_fallback if rewriter is not None else None,
    )
    payload = render_json(report)
    if json_path is not None:
        try:
            json_path.write_text(payload, encoding="utf-8")
        except OSError as exc:
            typer.echo(f"Could not write {json_path}: {exc}", err=True)
            raise typer.Exit(code=1) from exc

    if chosen == "json":
        typer.echo(safety_banner(), err=True)
        typer.echo(payload, nl=False)
        return
    typer.echo(render_markdown(report), nl=False)


@app.command("eval")
def eval_command(
    alerts: Path = typer.Option(
        default_alerts_dir(),
        "--alerts",
        help=(
            "JSON alert file or directory. Default: fixtures/alerts. "
            "Held-out set: fixtures/heldout/alerts."
        ),
    ),
    labels: Path = typer.Option(
        default_labels_path(),
        "--labels",
        help=(
            "Label JSON file. Default: fixtures/labels.json. "
            "Held-out labels: fixtures/heldout/labels.json."
        ),
    ),
    json_path: Path | None = typer.Option(
        None,
        "--json",
        help="Write the metrics, caveat, and mismatches to this JSON file.",
    ),
) -> None:
    """Compare rule severity to labels.

    Prints exact-match accuracy, within-one-level accuracy, and a confusion matrix.
    """
    try:
        loaded_alerts = load_alerts(alerts)
        loaded_labels = load_labels(labels)
        report = evaluate(loaded_alerts, loaded_labels, banner=safety_banner())
    except (FixtureLoadError, EvalError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    payload = render_eval_json(report)
    if json_path is not None:
        try:
            json_path.write_text(payload, encoding="utf-8")
        except OSError as exc:
            typer.echo(f"Could not write {json_path}: {exc}", err=True)
            raise typer.Exit(code=1) from exc
    typer.echo(render_eval_markdown(report), nl=False)
