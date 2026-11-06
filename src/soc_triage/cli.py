"""Command-line interface.

`run` triages a fixture file or directory with the rules path.
`eval` compares those scores to a label file.
`serve` exposes the same path on a local HTTP API when the api extra is installed.
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
from soc_triage.llm import SYNTHETIC_SEND_NOTICE, OpenAICompatibleClient, optional_note_client
from soc_triage.notes import fallback_message
from soc_triage.report import build_report, render_json, render_markdown, safety_banner

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=(
        "First-pass triage for synthetic SOC alerts. "
        "Demo and practice only — not a production SIEM."
    ),
)

_FORMATS = {"markdown", "json"}
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


class ApiExtraError(RuntimeError):
    """FastAPI or uvicorn is not installed."""


def _note_rewriter(llm_notes: bool) -> OpenAICompatibleClient | None:
    """Build a client only when the flag and provider config both allow it."""
    client, warning = optional_note_client(llm_notes)
    if warning is not None:
        typer.echo(warning, err=True)
        return None
    if client is not None:
        typer.echo(SYNTHETIC_SEND_NOTICE, err=True)
    return client


def _warn_note_fallback(alert_id: str, reason: str) -> None:
    typer.echo(fallback_message(alert_id, reason), err=True)


def load_api_runtime():
    """Import uvicorn and the app factory. Requires the api extra."""
    try:
        import uvicorn
        from soc_triage.api import create_app
    except ImportError as exc:
        raise ApiExtraError(
            'The API extra is not installed. Run: pip install -e ".[api]"'
        ) from exc
    return uvicorn, create_app


def _is_loopback(host: str) -> bool:
    return host.strip().lower() in _LOOPBACK_HOSTS


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


@app.command("serve")
def serve_command(
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Interface to bind. Default is 127.0.0.1. This demo has no authentication.",
    ),
    port: int = typer.Option(
        8000,
        "--port",
        min=1,
        max=65535,
        help="TCP port. Default is 8000.",
    ),
    llm_notes: bool = typer.Option(
        False,
        "--llm-notes",
        help=(
            "Rewrite draft notes with the configured model for every request. "
            "Off by default. A request can also pass llm_notes=true. "
            "Rules still set severity, confidence, needs_review, and reasons. "
            "Missing config, timeout, or invalid text keeps the template note."
        ),
    ),
) -> None:
    """Serve the local triage API. Loopback only unless you change --host.

    This demo does not authenticate callers. Add authentication before any
    network exposure. Install the extra with: pip install -e ".[api]"
    """
    chosen = host.strip()
    if not chosen:
        typer.echo("Host is required.", err=True)
        raise typer.Exit(code=2)

    try:
        uvicorn, create_app = load_api_runtime()
    except ApiExtraError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(safety_banner(), err=True)
    typer.echo(
        f"Local demo API at http://{chosen}:{port} (docs at /docs). "
        "No authentication. Synthetic alerts only.",
        err=True,
    )
    if not _is_loopback(chosen):
        typer.echo(
            "Binding beyond loopback. This demo has no authentication. "
            "Add auth before exposing it on a network.",
            err=True,
        )
    if llm_notes:
        _note_rewriter(True)
    uvicorn.run(
        create_app(llm_notes_default=llm_notes),
        host=chosen,
        port=port,
        log_level="info",
    )
