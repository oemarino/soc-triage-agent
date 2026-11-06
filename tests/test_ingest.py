"""Loader tests for bundled synthetic fixtures."""

from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from soc_triage.ingest import (
    FixtureLoadError,
    default_alerts_dir,
    default_heldout_alerts_dir,
    default_heldout_labels_path,
    default_labels_path,
    load_alerts,
    load_labels,
    parse,
)
from soc_triage.models import CATEGORIES, Alert, Severity

ROOT = Path(__file__).resolve().parents[1]
DOC_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
BANNED = ("mimikatz", "payload", "exploit", "psexec", "cobalt", "meterpreter")
SEED_FILES = {
    "brute_force.json",
    "phishing_url.json",
    "malware_hash.json",
    "lateral_movement.json",
    "policy_noise.json",
}


def _alert(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "SYN-BF-900",
        "timestamp": "2026-03-10T00:00:00Z",
        "source": "demo-auth-gateway",
        "category": "brute_force",
        "raw_fields": {"summary": "synthetic unit alert"},
    }
    base.update(overrides)
    return base


def _example_host(host: str) -> bool:
    return host == "example" or host.endswith(
        (".example", ".example.com", ".example.net", ".example.org")
    )


def test_default_paths_point_at_repo_fixtures() -> None:
    assert default_alerts_dir() == ROOT / "fixtures" / "alerts"
    assert default_labels_path() == ROOT / "fixtures" / "labels.json"
    assert default_heldout_alerts_dir() == ROOT / "fixtures" / "heldout" / "alerts"
    assert default_heldout_labels_path() == ROOT / "fixtures" / "heldout" / "labels.json"
    names = {path.name for path in default_alerts_dir().glob("*.json")}
    assert SEED_FILES <= names
    heldout_names = {path.name for path in default_heldout_alerts_dir().glob("*.json")}
    assert SEED_FILES <= heldout_names


def test_bundled_fixtures_validate_and_cover_categories() -> None:
    alerts = load_alerts(default_alerts_dir())
    assert len(alerts) >= 20
    counts = Counter(alert.category for alert in alerts)
    assert set(CATEGORIES) <= set(counts)
    assert all(counts[name] >= 4 for name in CATEGORIES)
    assert [alert.id for alert in alerts] == sorted(alert.id for alert in alerts)
    assert len({alert.id for alert in alerts}) == len(alerts)

    for alert in alerts:
        again = type(alert).model_validate(alert.model_dump(mode="json"))
        assert again == alert


def test_parse_accepts_object_and_list(tmp_path: Path) -> None:
    single = tmp_path / "one.json"
    single.write_text(json.dumps(_alert()), encoding="utf-8")
    batch = tmp_path / "two.json"
    batch.write_text(
        json.dumps([_alert(id="SYN-BF-901"), _alert(id="SYN-BF-902")]),
        encoding="utf-8",
    )
    assert [alert.id for alert in load_alerts(single)] == ["SYN-BF-900"]
    assert [alert.id for alert in parse(json.loads(batch.read_text(encoding="utf-8")))] == [
        "SYN-BF-901",
        "SYN-BF-902",
    ]


def test_directory_loader_ignores_non_json_and_sorts(tmp_path: Path) -> None:
    (tmp_path / "b.json").write_text(json.dumps(_alert(id="SYN-BF-902")), encoding="utf-8")
    (tmp_path / "a.json").write_text(json.dumps(_alert(id="SYN-BF-901")), encoding="utf-8")
    (tmp_path / "notes.txt").write_text("not an alert", encoding="utf-8")
    assert [alert.id for alert in load_alerts(tmp_path)] == ["SYN-BF-901", "SYN-BF-902"]


def test_loader_rejects_invalid_duplicate_and_missing(tmp_path: Path) -> None:
    missing = tmp_path / "absent"
    with pytest.raises(FixtureLoadError) as missing_exc:
        load_alerts(missing)
    assert missing_exc.value.path == missing

    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(FixtureLoadError):
        load_alerts(empty)

    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    with pytest.raises(FixtureLoadError) as bad_exc:
        load_alerts(bad)
    assert bad_exc.value.path == bad

    invalid = tmp_path / "invalid.json"
    invalid.write_text(json.dumps(_alert(category="not-a-category")), encoding="utf-8")
    with pytest.raises(FixtureLoadError) as invalid_exc:
        load_alerts(invalid)
    assert invalid_exc.value.path == invalid

    dupes = tmp_path / "dupes"
    dupes.mkdir()
    (dupes / "one.json").write_text(json.dumps(_alert(id="SYN-BF-901")), encoding="utf-8")
    (dupes / "two.json").write_text(json.dumps(_alert(id="SYN-BF-901")), encoding="utf-8")
    with pytest.raises(FixtureLoadError, match="Duplicate alert id"):
        load_alerts(dupes)


def test_labels_are_a_subset_of_known_alerts() -> None:
    alerts = load_alerts(default_alerts_dir())
    labels = load_labels(default_labels_path())
    alert_ids = {alert.id for alert in alerts}
    label_ids = [label.id for label in labels.labels]
    assert len(label_ids) >= 10
    assert set(label_ids) < alert_ids
    assert {label.severity for label in labels.labels} == set(Severity)

    by_id = {alert.id: alert for alert in alerts}
    labeled_categories = {by_id[label_id].category for label_id in label_ids}
    assert set(CATEGORIES) <= labeled_categories
    assert "synthetic" in labels.description.lower()
    assert "5737" in labels.provenance


def test_heldout_set_loads_and_is_fully_labeled() -> None:
    alerts = load_alerts(default_heldout_alerts_dir())
    labels = load_labels(default_heldout_labels_path())
    tuning = load_alerts(default_alerts_dir())
    assert len(alerts) == 30
    counts = Counter(alert.category for alert in alerts)
    assert set(CATEGORIES) <= set(counts)
    assert all(counts[name] >= 4 for name in CATEGORIES)
    alert_ids = {alert.id for alert in alerts}
    label_ids = {label.id for label in labels.labels}
    assert label_ids == alert_ids
    assert alert_ids.isdisjoint({alert.id for alert in tuning})
    assert labels.held_out is True
    assert labels.dataset == "synthetic-soc-triage-heldout"
    assert {label.severity for label in labels.labels} == set(Severity)
    assert "before any eval run" in labels.provenance
    assert "5737" in labels.provenance
    assert "synthetic" in labels.description.lower()
    heldout_blob = "\n".join(
        path.read_text(encoding="utf-8") for path in default_heldout_alerts_dir().glob("*.json")
    )
    heldout_blob += default_heldout_labels_path().read_text(encoding="utf-8")
    _assert_synthetic(alerts, heldout_blob)


def test_fixtures_stay_synthetic() -> None:
    alerts = load_alerts(default_alerts_dir())
    blob = "\n".join(path.read_text(encoding="utf-8") for path in default_alerts_dir().glob("*.json"))
    blob += (ROOT / "fixtures" / "labels.json").read_text(encoding="utf-8")
    _assert_synthetic(alerts, blob)


def _assert_synthetic(alerts: list[Alert], blob: str) -> None:
    lowered = blob.lower()
    for word in BANNED:
        assert word not in lowered

    for match in IPV4.findall(blob):
        address = ipaddress.ip_address(match)
        assert any(address in net for net in DOC_NETS), match
    for email in EMAIL.findall(blob):
        assert email.endswith(("@example.com", "@example.net", "@example.org")), email

    for alert in alerts:
        for key, value in alert.raw_fields.items():
            assert key not in {"password", "passwd", "secret", "token", "ssn", "api_key"}
            if key == "user":
                assert isinstance(value, str)
                assert value.startswith(("demo.", "svc-"))
            if key == "hostname" and isinstance(value, str):
                assert value.endswith(".example.com")
        for ioc in alert.iocs:
            if ioc.type.value == "ipv4":
                address = ipaddress.ip_address(ioc.value)
                assert any(address in net for net in DOC_NETS)
            elif ioc.type.value == "sha256":
                assert len(set(ioc.value)) == 1
            elif ioc.type.value == "domain":
                assert _example_host(ioc.value)
            elif ioc.type.value == "url":
                host = urlsplit(ioc.value).hostname
                assert host is not None
                assert _example_host(host)
