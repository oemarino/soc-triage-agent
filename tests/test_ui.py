"""Web UI tests. Skipped when the api extra is not installed.

The page is static HTML on the existing FastAPI app. These tests check
that GET / serves it, that the page's sample path still ranks through
POST /triage/batch, and that the documented eval numbers are unchanged.
"""

from __future__ import annotations

import http.client
import importlib.util
import json
import re
import urllib.request
from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason='API extra is not installed. Run: pip install -e ".[api]"')
if importlib.util.find_spec("httpx2") is None and importlib.util.find_spec("httpx") is None:
    pytest.skip(
        'FastAPI TestClient needs httpx2. Install the dev extra: pip install -e ".[dev]"',
        allow_module_level=True,
    )

from fastapi.testclient import TestClient

from soc_triage.api import create_app
from soc_triage.cli import app as cli_app
from soc_triage.eval import evaluate
from soc_triage.ingest import (
    default_alerts_dir,
    default_heldout_alerts_dir,
    default_heldout_labels_path,
    default_labels_path,
    load_alerts,
    load_labels,
)
from soc_triage.llm import ENV_API_KEY, ENV_BASE_URL, ENV_MODEL, ENV_PROVIDER, ENV_TIMEOUT
from soc_triage.report import safety_banner
from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parents[1]
RUNNER = CliRunner()

PAGE_MARKERS = (
    'id="alert-json"',
    'id="alert-file"',
    'id="load-sample"',
    'id="llm-notes"',
    'id="ranked"',
    "Alert id",
    "Type",
    "Severity",
    "Confidence",
    "/triage/batch",
    "/fixtures/sample",
    "AI-drafted, analyst review required.",
    "note_source",
    "127.0.0.1",
    "No authentication",
    "Demo only",
    "sev-critical",
    "sev-high",
    "sev-medium",
    "sev-low",
    "sev-info",
)


@pytest.fixture
def client() -> TestClient:
    with TestClient(create_app()) as test_client:
        yield test_client


def _cli_report() -> dict:
    result = RUNNER.invoke(cli_app, ["run", str(default_alerts_dir()), "--format", "json"])
    assert result.exit_code == 0, result.stderr
    return json.loads(result.stdout)


def test_ui_route_returns_the_demo_page(client: TestClient) -> None:
    response = client.get("/", headers={"Origin": "https://evil.example"})
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert response.headers.get("access-control-allow-origin") is None
    html = response.text
    for marker in PAGE_MARKERS:
        assert marker in html
    checkbox = re.search(r"<input\b[^>]*\bid=\"llm-notes\"[^>]*>", html)
    assert checkbox is not None
    assert 'type="checkbox"' in checkbox.group(0)
    assert "checked" not in checkbox.group(0)
    assert 'if (llmNotes.checked)' in html
    assert 'params.set("llm_notes", "true")' in html
    assert 'type="password"' not in html
    assert "No API key is required" in html
    assert "/ui-assets/fonts/geist-sans.woff2" in html
    assert "border-radius: 999px" in html
    font = client.get("/ui-assets/fonts/geist-sans.woff2")
    assert font.status_code == 200
    assert "woff2" in font.headers["content-type"]

    spec = client.get("/openapi.json")
    assert spec.status_code == 200
    paths = spec.json()["paths"]
    assert "/" in paths
    assert "/fixtures/sample" in paths
    assert set(paths) >= {"/health", "/triage", "/triage/batch", "/fixtures/demo"}
    description = spec.json()["info"]["description"].lower()
    assert "authentication" in description
    assert "127.0.0.1" in description
    assert "not a production siem" in description


def test_sample_page_path_matches_cli_and_leaves_endpoints_unchanged(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    for key in (ENV_PROVIDER, ENV_BASE_URL, ENV_MODEL, ENV_API_KEY, ENV_TIMEOUT):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(ENV_PROVIDER, "openai_compatible")
    monkeypatch.setenv(ENV_BASE_URL, "https://api.x.ai/v1")
    monkeypatch.setenv(ENV_MODEL, "grok-test")
    monkeypatch.setenv(ENV_API_KEY, "test-not-a-real-key")

    def explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("network is disabled in tests")

    monkeypatch.setattr(urllib.request, "urlopen", explode)
    monkeypatch.setattr(http.client.HTTPConnection, "connect", explode)
    monkeypatch.setattr(http.client.HTTPSConnection, "connect", explode)
    monkeypatch.setattr("soc_triage.llm._urlopen_post", explode)

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json() == {"status": "ok", "mode": "synthetic"}

    sample = client.get("/fixtures/sample")
    assert sample.status_code == 200, sample.text
    alerts = sample.json()
    assert len(alerts) == 25
    assert {item["category"] for item in alerts} >= {
        "brute_force",
        "phishing_url",
        "malware_hash",
        "lateral_movement",
        "policy_noise",
    }

    batch = client.post("/triage/batch", json=alerts)
    assert batch.status_code == 200, batch.text
    body = batch.json()
    cli = _cli_report()
    assert body["banner"] == cli["banner"] == safety_banner()
    assert body["count"] == cli["count"] == 25
    assert body["results"] == cli["results"]
    assert body["severity_counts"] == {
        "critical": 4,
        "high": 4,
        "medium": 5,
        "low": 5,
        "info": 7,
    }
    assert all(row["note_source"] == "rules" for row in body["results"])
    assert "test-not-a-real-key" not in batch.text
    assert [row["severity"] for row in body["results"][:4]] == ["critical"] * 4

    demo = client.get("/fixtures/demo")
    assert demo.status_code == 200, demo.text
    assert demo.json()["results"] == cli["results"]
    assert demo.json()["severity_counts"] == body["severity_counts"]

    one = next(item for item in alerts if item["id"] == "SYN-BF-001")
    single = client.post("/triage", json=one)
    assert single.status_code == 200, single.text
    single_body = single.json()
    cli_row = next(row for row in cli["results"] if row["id"] == "SYN-BF-001")
    assert single_body["severity"] == cli_row["severity"] == "critical"
    assert single_body["note_source"] == "rules"
    assert single_body["reasons"] == cli_row["reasons"]
    assert single_body["note"] == cli_row["note"]


def test_eval_numbers_are_unchanged() -> None:
    tuning = evaluate(
        load_alerts(default_alerts_dir()),
        load_labels(default_labels_path()),
        banner=safety_banner(),
    )
    assert tuning.labeled_count == 20
    assert tuning.exact_matches == 20
    assert tuning.within_one_matches == 20
    assert tuning.accuracy == 1.0

    heldout = evaluate(
        load_alerts(default_heldout_alerts_dir()),
        load_labels(default_heldout_labels_path()),
        banner=safety_banner(),
    )
    assert heldout.alert_count == 30
    assert heldout.labeled_count == 30
    assert heldout.exact_matches == 24
    assert heldout.within_one_matches == 27
    assert heldout.accuracy == 24 / 30
    assert heldout.within_one_accuracy == 27 / 30
    assert [
        (item.alert_id, item.labeled.value, item.predicted.value) for item in heldout.mismatches
    ] == [
        ("HO-BF-002", "high", "medium"),
        ("HO-BF-003", "critical", "medium"),
        ("HO-LM-006", "high", "medium"),
        ("HO-MH-006", "high", "medium"),
        ("HO-PH-004", "critical", "medium"),
        ("HO-PN-006", "medium", "info"),
    ]
