"""CLI tests for `soc-triage run` using Typer's CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from soc_triage.cli import app, safety_banner

ROOT = Path(__file__).resolve().parents[1]
ALERTS = ROOT / "fixtures" / "alerts"
RUNNER = CliRunner()


def test_run_directory_prints_banner_and_ranked_summary() -> None:
    result = RUNNER.invoke(app, ["run", str(ALERTS)])
    assert result.exit_code == 0, result.stderr
    assert result.stdout.startswith(safety_banner())
    assert "SYN-BF-001" in result.stdout
    assert "critical" in result.stdout
    assert "needs review" in result.stdout.lower()
    assert result.stdout.index("SYN-BF-001") < result.stdout.index("SYN-PN-005")


def test_run_single_file_and_json_stdout() -> None:
    result = RUNNER.invoke(
        app,
        ["run", str(ALERTS / "brute_force.json"), "--format", "json"],
    )
    assert result.exit_code == 0, result.stderr
    assert safety_banner() in result.stderr
    payload = json.loads(result.stdout)
    assert payload["count"] == 5
    assert payload["banner"] == safety_banner()
    assert [row["id"] for row in payload["results"]][0] == "SYN-BF-001"
    assert payload["results"][0]["category"] == "brute_force"


def test_run_writes_json_file(tmp_path: Path) -> None:
    destination = tmp_path / "triage.json"
    result = RUNNER.invoke(
        app,
        ["run", str(ALERTS), "--json", str(destination), "--format", "markdown"],
    )
    assert result.exit_code == 0, result.stderr
    assert result.stdout.startswith(safety_banner())
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["count"] == 25
    assert payload["results"][0]["severity"] == "critical"
    assert "note" in payload["results"][0]
    assert "Rule reasons" in payload["results"][0]["note"]


def test_run_rejects_bad_json_and_unknown_format(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    invalid = RUNNER.invoke(app, ["run", str(bad)])
    assert invalid.exit_code == 1
    assert "Invalid JSON" in invalid.stderr

    missing = RUNNER.invoke(app, ["run", str(tmp_path / "missing")])
    assert missing.exit_code != 0

    unknown = RUNNER.invoke(app, ["run", str(ALERTS), "--format", "xml"])
    assert unknown.exit_code == 2
    assert "markdown or json" in unknown.stderr


def test_eval_command_is_registered() -> None:
    result = RUNNER.invoke(app, ["eval", "--help"])
    assert result.exit_code == 0
    assert "--alerts" in result.stdout
    assert "--labels" in result.stdout
    assert "--json" in result.stdout
