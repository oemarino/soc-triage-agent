"""T1 smoke test: the package imports and the CLI skeleton loads."""

from __future__ import annotations

import json
from pathlib import Path

import soc_triage
from soc_triage.cli import app, safety_banner
from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parents[1]


def test_package_version() -> None:
    assert soc_triage.__version__
    assert soc_triage.Alert.__name__ == "Alert"


def test_schema_modules_import() -> None:
    import soc_triage.ingest
    import soc_triage.models

    assert soc_triage.models.Alert is soc_triage.Alert
    assert callable(soc_triage.ingest.load_alerts)


def test_notes_module_is_implemented() -> None:
    import soc_triage.notes as notes

    assert not hasattr(notes, "TODO")
    assert callable(notes.draft_note)
    assert callable(notes.resolve_note)


def test_cli_help_lists_later_commands() -> None:
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "run" in result.stdout
    assert "eval" in result.stdout


def test_safety_banner_states_synthetic_and_human_review() -> None:
    text = safety_banner().lower()
    assert "synthetic" in text
    assert "human" in text


def test_labels_file_is_documented_json() -> None:
    data = json.loads((ROOT / "fixtures" / "labels.json").read_text(encoding="utf-8"))
    assert isinstance(data["labels"], list)
    assert data["labels"]
    assert "synthetic" in data["description"].lower()
