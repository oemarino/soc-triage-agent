"""Load synthetic JSON fixtures and validate them as alerts.

Filesystem only. This module does not call a SIEM or any network service.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from soc_triage.models import Alert, LabelSet


class FixtureLoadError(ValueError):
    """A fixture file is missing or failed validation."""

    def __init__(self, message: str, *, path: Path | None = None) -> None:
        self.path = path
        super().__init__(message)


def default_alerts_dir() -> Path:
    """Repo ``fixtures/alerts`` directory, resolved from this source file."""
    return Path(__file__).resolve().parents[2] / "fixtures" / "alerts"


def default_labels_path() -> Path:
    """Repo ``fixtures/labels.json`` path."""
    return Path(__file__).resolve().parents[2] / "fixtures" / "labels.json"


def default_heldout_alerts_dir() -> Path:
    """Repo ``fixtures/heldout/alerts`` directory."""
    return Path(__file__).resolve().parents[2] / "fixtures" / "heldout" / "alerts"


def default_heldout_labels_path() -> Path:
    """Repo ``fixtures/heldout/labels.json`` path."""
    return Path(__file__).resolve().parents[2] / "fixtures" / "heldout" / "labels.json"


def parse(payload: object) -> list[Alert]:
    """Validate one alert object or a list of alert objects.

    This is the ``ingest.parse`` step in plan.md.
    """
    if isinstance(payload, dict):
        items: list[object] = [payload]
    elif isinstance(payload, list):
        items = list(payload)
    else:
        raise FixtureLoadError("Alert JSON must be an object or a list of objects")
    if not items:
        raise FixtureLoadError("Alert list is empty")

    alerts: list[Alert] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise FixtureLoadError(f"Alert at index {index} is not an object")
        try:
            alerts.append(Alert.model_validate(item))
        except ValidationError as exc:
            raise FixtureLoadError(f"Alert at index {index} failed validation: {exc}") from exc
    return alerts


def load_alerts(path: str | Path) -> list[Alert]:
    """Load alerts from a JSON file or a directory of JSON files.

    Directory reads are non-recursive and ignore non-JSON files. Results are
    sorted by alert id. Duplicate ids raise ``FixtureLoadError``.
    """
    files = _json_files(Path(path))
    alerts: list[Alert] = []
    seen: dict[str, Path] = {}
    for file in files:
        for alert in _parse_file(file):
            previous = seen.get(alert.id)
            if previous is not None:
                where = file.name if previous == file else f"{file.name} and {previous.name}"
                raise FixtureLoadError(f"Duplicate alert id {alert.id} in {where}", path=file)
            seen[alert.id] = file
            alerts.append(alert)
    alerts.sort(key=lambda alert: alert.id)
    return alerts


def load_labels(path: str | Path) -> LabelSet:
    """Load a label file such as ``fixtures/labels.json``."""
    source = Path(path)
    if not source.is_file():
        raise FixtureLoadError(f"Label file not found: {source}", path=source)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FixtureLoadError(f"Invalid JSON in {source.name}: {exc}", path=source) from exc
    try:
        return LabelSet.model_validate(payload)
    except ValidationError as exc:
        raise FixtureLoadError(
            f"Labels in {source.name} failed validation: {exc}",
            path=source,
        ) from exc


def _json_files(source: Path) -> list[Path]:
    if not source.exists():
        raise FixtureLoadError(f"Fixture path not found: {source}", path=source)
    if source.is_file():
        if source.suffix.lower() != ".json":
            raise FixtureLoadError(f"Not a JSON file: {source.name}", path=source)
        return [source]
    if not source.is_dir():
        raise FixtureLoadError(
            f"Fixture path is not a file or directory: {source}",
            path=source,
        )
    files = sorted(
        child
        for child in source.iterdir()
        if child.is_file() and child.suffix.lower() == ".json"
    )
    if not files:
        raise FixtureLoadError(f"No JSON alerts in {source}", path=source)
    return files


def _parse_file(path: Path) -> list[Alert]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FixtureLoadError(f"Invalid JSON in {path.name}: {exc}", path=path) from exc
    try:
        return parse(payload)
    except FixtureLoadError as exc:
        if exc.path is None:
            raise FixtureLoadError(f"{path.name}: {exc}", path=path) from exc
        raise
