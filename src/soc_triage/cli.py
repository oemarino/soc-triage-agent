"""Command-line interface.

`run` triages a fixture file or directory with the rules path.
`eval` compares those scores to a label file.
Every real run states synthetic/demo mode. No API key required.
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
) -> None:
    """Rank fixture alerts with the rules engine. No API key required."""
    chosen = output_format.lower()
    if chosen not in _FORMATS:
        typer.echo("Unknown format. Use markdown or json.", err=True)
        raise typer.Exit(code=2)

    try:
        alerts = load_alerts(path)
    except FixtureLoadError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    report = build_report(alerts, banner=safety_banner())
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
