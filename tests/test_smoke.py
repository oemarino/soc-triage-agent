"""T1 smoke test: the package imports and the CLI skeleton loads."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import soc_triage
from soc_triage.cli import app, safety_banner
from typer.testing import CliRunner

MODULES = (
    "soc_triage.models",
    "soc_triage.ingest",
    "soc_triage.rules",
    "soc_triage.notes",
    "soc_triage.report",
    "soc_triage.cli",
    "soc_triage.eval",
)

ROOT = Path(__file__).resolve().parents[1]


def test_package_version() -> None:
    assert soc_triage.__version__


def test_stub_modules_import_and_name_their_task() -> None:
    for name in MODULES:
        module = importlib.import_module(name)
        assert isinstance(module.TODO, str)
        assert module.TODO.startswith("T")


def test_cli_help_lists_later_commands() -> None:
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "run" in result.stdout
    assert "eval" in result.stdout


def test_safety_banner_states_synthetic_and_human_review() -> None:
    text = safety_banner().lower()
    assert "synthetic" in text
    assert "human" in text


def test_labels_placeholder() -> None:
    data = json.loads((ROOT / "fixtures" / "labels.json").read_text(encoding="utf-8"))
    assert data["labels"] == []
    assert "synthetic" in data["description"].lower()
