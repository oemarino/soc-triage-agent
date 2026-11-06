"""HTTP API tests. Skipped when the api extra is not installed."""

from __future__ import annotations

import asyncio
import http.client
import importlib.util
import json
import logging
import urllib.request
from collections import Counter
from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason='API extra is not installed. Run: pip install -e ".[api]"')
if importlib.util.find_spec("httpx2") is None and importlib.util.find_spec("httpx") is None:
    pytest.skip(
        'FastAPI TestClient needs httpx2. Install the dev extra: pip install -e ".[dev]"',
        allow_module_level=True,
    )

from fastapi.testclient import TestClient

from soc_triage.api import MAX_BATCH_SIZE, MAX_BODY_BYTES, BodySizeLimit, create_app
from soc_triage.cli import app as cli_app
from soc_triage.cli import safety_banner
from soc_triage.llm import ENV_API_KEY, ENV_BASE_URL, ENV_MODEL, ENV_PROVIDER, ENV_TIMEOUT
from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parents[1]
ALERTS = ROOT / "fixtures" / "alerts"
RUNNER = CliRunner()

_COMPARE = (
    "id",
    "severity",
    "confidence",
    "needs_review",
    "reasons",
    "note",
    "note_source",
)


@pytest.fixture
def client() -> TestClient:
    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture
def clean_llm_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for key in (ENV_PROVIDER, ENV_BASE_URL, ENV_MODEL, ENV_API_KEY, ENV_TIMEOUT):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.chdir(tmp_path)


def _forbid_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("network is disabled in tests")

    monkeypatch.setattr(urllib.request, "urlopen", explode)
    monkeypatch.setattr(http.client.HTTPConnection, "connect", explode)
    monkeypatch.setattr(http.client.HTTPSConnection, "connect", explode)


def _alert_payloads() -> list[dict]:
    payloads: list[dict] = []
    for path in sorted(ALERTS.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            payloads.extend(data)
        else:
            payloads.append(data)
    return payloads


def _one_alert() -> dict:
    return next(item for item in _alert_payloads() if item["id"] == "SYN-BF-001")


def _cli_report() -> dict:
    result = RUNNER.invoke(cli_app, ["run", str(ALERTS), "--format", "json"])
    assert result.exit_code == 0, result.stderr
    return json.loads(result.stdout)


def _project(row: dict) -> dict:
    return {key: row[key] for key in _COMPARE}


def _minimal(index: int) -> dict:
    return {
        "id": f"B{index:03d}",
        "timestamp": "2026-03-10T15:00:00Z",
        "source": "demo-policy-monitor",
        "category": "policy_noise",
        "raw_fields": {
            "summary": "Synthetic batch row for the size cap.",
            "allowlisted": True,
            "context_complete": True,
        },
    }


def _chat_response(content: str) -> bytes:
    return json.dumps(
        {"choices": [{"message": {"role": "assistant", "content": content}}]}
    ).encode("utf-8")


def test_health_docs_and_no_cors_or_auth(client: TestClient) -> None:
    health = client.get("/health", headers={"Origin": "https://evil.example"})
    assert health.status_code == 200
    assert health.json() == {"status": "ok", "mode": "synthetic"}
    assert health.headers.get("access-control-allow-origin") is None

    docs = client.get("/docs")
    assert docs.status_code == 200
    assert "text/html" in docs.headers["content-type"]

    spec = client.get("/openapi.json")
    assert spec.status_code == 200
    document = spec.json()
    assert set(document["paths"]) >= {"/health", "/triage", "/triage/batch", "/fixtures/demo"}
    assert "securitySchemes" not in document.get("components", {})
    assert not document.get("security")
    description = document["info"]["description"].lower()
    assert "authentication" in description
    assert "127.0.0.1" in description
    assert "not a production siem" in description


def test_single_triage_matches_cli_for_the_same_fixture(client: TestClient) -> None:
    cli_row = next(row for row in _cli_report()["results"] if row["id"] == "SYN-BF-001")
    response = client.post("/triage", json=_one_alert())
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["banner"] == safety_banner()
    assert _project(body) == _project(cli_row)
    assert body["severity"] == "critical"
    assert body["note_source"] == "rules"
    assert "Traceback" not in response.text


def test_batch_ranking_and_counts_match_cli_run(client: TestClient) -> None:
    cli = _cli_report()
    response = client.post("/triage/batch", json=_alert_payloads())
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["banner"] == cli["banner"] == safety_banner()
    assert body["mode"] == "synthetic"
    assert body["count"] == cli["count"] == 25
    assert body["results"] == cli["results"]
    counted = Counter(row["severity"] for row in cli["results"])
    assert body["severity_counts"] == {
        "critical": counted["critical"],
        "high": counted["high"],
        "medium": counted["medium"],
        "low": counted["low"],
        "info": counted["info"],
    }
    assert body["severity_counts"] == {
        "critical": 4,
        "high": 4,
        "medium": 5,
        "low": 5,
        "info": 7,
    }


def test_fixtures_demo_matches_cli_run(client: TestClient) -> None:
    response = client.get("/fixtures/demo")
    assert response.status_code == 200, response.text
    body = response.json()
    cli = _cli_report()
    assert body["results"] == cli["results"]
    assert body["count"] == 25
    assert body["severity_counts"]["critical"] == 4


def test_invalid_payload_is_422_without_a_stack_trace(client: TestClient) -> None:
    missing = client.post("/triage", json={"id": "SYN-BAD"})
    assert missing.status_code == 422
    assert "Traceback" not in missing.text
    assert 'File "' not in missing.text
    assert missing.json()["detail"]

    alert = _one_alert()
    alert["extra_field"] = "nope"
    extra = client.post("/triage", json=alert)
    assert extra.status_code == 422
    assert "Traceback" not in extra.text

    malformed = client.post(
        "/triage",
        content=b"{",
        headers={"content-type": "application/json"},
    )
    assert malformed.status_code == 422
    assert "Traceback" not in malformed.text

    listed = client.post("/triage", json=[_one_alert()])
    assert listed.status_code == 422


def test_oversize_and_empty_batches_are_rejected(client: TestClient) -> None:
    too_many = client.post(
        "/triage/batch",
        json=[_minimal(index) for index in range(MAX_BATCH_SIZE + 1)],
    )
    assert too_many.status_code == 422
    assert "Traceback" not in too_many.text

    empty = client.post("/triage/batch", json=[])
    assert empty.status_code == 422

    duplicate = client.post("/triage/batch", json=[_minimal(1), _minimal(1)])
    assert duplicate.status_code == 422
    assert duplicate.json()["detail"] == "Duplicate alert id B001"
    assert "Traceback" not in duplicate.text

    accepted = client.post(
        "/triage/batch",
        json=[_minimal(index) for index in range(MAX_BATCH_SIZE)],
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["count"] == MAX_BATCH_SIZE


def test_request_body_over_the_limit_is_rejected(client: TestClient) -> None:
    payload = b'{"pad":"' + (b"a" * MAX_BODY_BYTES)
    response = client.post(
        "/triage",
        content=payload,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413
    assert str(MAX_BODY_BYTES) in response.text
    assert "Traceback" not in response.text


def test_body_limit_does_not_trust_a_short_content_length() -> None:
    called = False

    async def downstream(scope, receive, send) -> None:
        nonlocal called
        called = True
        await receive()

    wrapped = BodySizeLimit(downstream, max_bytes=4)
    sent: list[dict] = []

    async def send(message) -> None:
        sent.append(message)

    async def receive():
        return {"type": "http.request", "body": b"abcdef", "more_body": False}

    asyncio.run(
        wrapped(
            {"type": "http", "headers": [(b"content-length", b"3")]},
            receive,
            send,
        )
    )
    assert called is False
    assert sent[0]["status"] == 413

    async def unread():
        raise AssertionError("body should not be read")

    sent.clear()
    asyncio.run(
        wrapped(
            {"type": "http", "headers": [(b"content-length", b"100")]},
            unread,
            send,
        )
    )
    assert sent[0]["status"] == 413


def test_llm_notes_are_off_by_default(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    clean_llm_env: None,
) -> None:
    _forbid_network(monkeypatch)
    monkeypatch.setenv(ENV_PROVIDER, "openai_compatible")
    monkeypatch.setenv(ENV_BASE_URL, "https://api.x.ai/v1")
    monkeypatch.setenv(ENV_MODEL, "grok-test")
    monkeypatch.setenv(ENV_API_KEY, "test-not-a-real-key")
    calls = {"n": 0}

    def post(request: urllib.request.Request, timeout: float) -> bytes:
        calls["n"] += 1
        raise AssertionError("client should not be built")

    monkeypatch.setattr("soc_triage.llm._urlopen_post", post)
    response = client.post("/triage", json=_one_alert())
    assert response.status_code == 200, response.text
    body = response.json()
    assert calls["n"] == 0
    assert body["note_source"] == "rules"
    assert "Rule reasons" in body["note"]
    assert "test-not-a-real-key" not in response.text


def test_llm_flag_without_config_falls_back(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    clean_llm_env: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _forbid_network(monkeypatch)

    def post(request: urllib.request.Request, timeout: float) -> bytes:
        raise AssertionError("request sent")

    monkeypatch.setattr("soc_triage.llm._urlopen_post", post)
    with caplog.at_level(logging.WARNING, logger="soc_triage.api"):
        response = client.post("/triage?llm_notes=true", json=_one_alert())
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["note_source"] == "rules"
    assert "Rule reasons" in body["note"]
    assert body["severity"] == "critical"
    assert "No request was sent" in caplog.text
    assert "test-not-a-real-key" not in response.text


def test_llm_flag_keeps_rule_severity(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    clean_llm_env: None,
) -> None:
    monkeypatch.setenv(ENV_PROVIDER, "openai_compatible")
    monkeypatch.setenv(ENV_BASE_URL, "https://api.x.ai/v1")
    monkeypatch.setenv(ENV_MODEL, "grok-test")
    monkeypatch.setenv(ENV_API_KEY, "test-not-a-real-key")
    calls = {"n": 0}

    def post(request: urllib.request.Request, timeout: float) -> bytes:
        calls["n"] += 1
        assert request.get_header("Authorization") == "Bearer test-not-a-real-key"
        return _chat_response("AI note body for the analyst.")

    monkeypatch.setattr("soc_triage.llm._urlopen_post", post)
    rules = client.post("/triage", json=_one_alert()).json()
    rewritten = client.post("/triage?llm_notes=true", json=_one_alert())
    assert rewritten.status_code == 200, rewritten.text
    body = rewritten.json()
    assert calls["n"] == 1
    assert body["note_source"] == "llm"
    assert body["note"] == "AI note body for the analyst."
    assert body["severity"] == rules["severity"]
    assert body["confidence"] == rules["confidence"]
    assert body["needs_review"] == rules["needs_review"]
    assert body["reasons"] == rules["reasons"]
    assert "test-not-a-real-key" not in rewritten.text


def test_server_llm_notes_setting_is_opt_in(
    monkeypatch: pytest.MonkeyPatch,
    clean_llm_env: None,
) -> None:
    monkeypatch.setenv(ENV_PROVIDER, "openai_compatible")
    monkeypatch.setenv(ENV_BASE_URL, "http://127.0.0.1:9/v1")
    monkeypatch.setenv(ENV_MODEL, "llama3.2")
    calls = {"n": 0}

    def post(request: urllib.request.Request, timeout: float) -> bytes:
        calls["n"] += 1
        return _chat_response("Server drafted note.")

    monkeypatch.setattr("soc_triage.llm._urlopen_post", post)
    with TestClient(create_app()) as off:
        assert off.post("/triage", json=_one_alert()).json()["note_source"] == "rules"
    assert calls["n"] == 0
    with TestClient(create_app(llm_notes_default=True)) as on:
        body = on.post("/triage", json=_one_alert()).json()
    assert calls["n"] == 1
    assert body["note_source"] == "llm"
    assert body["note"] == "Server drafted note."
    assert body["severity"] == "critical"
