"""Command-line interface.

TODO(T4): `soc-triage run` triages a fixture directory with the rules path.
TODO(T5): `soc-triage eval` reports metrics against fixtures/labels.json.
Every real run must print the synthetic/demo banner. No API key required.
"""

from __future__ import annotations

import typer

TODO = "T4"

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


def safety_banner() -> str:
    """Banner required on every triage run (spec: safety banner)."""
    return SAFETY_BANNER


@app.callback()
def main() -> None:
    """Portfolio SOC triage assistant. Synthetic data only."""


@app.command("run")
def run_command() -> None:
    """Rank fixture alerts. Implemented in T4."""
    typer.echo(safety_banner())
    typer.echo(
        "soc-triage run is not implemented yet. "
        "Next work is T2 (schema + fixtures), then T4 (tasks.md)."
    )
    raise typer.Exit(code=0)


@app.command("eval")
def eval_command() -> None:
    """Score predictions against labels. Implemented in T5."""
    typer.echo(safety_banner())
    typer.echo("soc-triage eval is not implemented yet. See T5 in tasks.md.")
    raise typer.Exit(code=0)
