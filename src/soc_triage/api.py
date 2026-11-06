"""Local HTTP API for the same triage path the CLI uses.

Install the extra with ``pip install -e ".[api]"``. The process binds
loopback from ``soc-triage serve`` and does not authenticate callers.
Add authentication before any network exposure. This is a demo, not a SIEM.

``GET /`` is one static HTML page. It posts alert JSON to
``POST /triage/batch``. ``GET /fixtures/sample`` returns the bundled alerts
unscored so that page can load them and post the same list.

``POST /triage`` and ``POST /triage/batch`` call ``report.build_report``,
so severity, confidence, needs_review, reasons, and notes match
``soc-triage run``. LLM notes stay off unless a request opts in or the
server was started with ``--llm-notes``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from soc_triage import __version__
from soc_triage.ingest import FixtureLoadError, default_alerts_dir, load_alerts
from soc_triage.llm import SYNTHETIC_SEND_NOTICE, optional_note_client
from soc_triage.models import Alert, Reason, Severity
from soc_triage.notes import fallback_message
from soc_triage.report import RankedAlert, TriageReport, build_report, safety_banner, severity_counts

logger = logging.getLogger("soc_triage.api")

MAX_BATCH_SIZE = 500
MAX_BODY_BYTES = 1_048_576

_DESCRIPTION = """
Local demo API for synthetic SOC alert triage.

The service recommends a severity and drafts a note. A human makes the final
call. It does not close, block, or notify anyone. There is no authentication
and no CORS wildcard. The CLI binds 127.0.0.1 unless you change --host.
Add authentication before exposing this process on a network.
Not a production SIEM.

Severity, confidence, needs_review, and reasons come from the rules engine.
A model may rewrite the note only when the request sets llm_notes=true or
the server was started with --llm-notes, and only when provider settings are
complete. Missing config, timeout, or invalid text keeps the template note.

GET / serves one static HTML page for this same local demo. The page posts
alert JSON to POST /triage/batch. GET /fixtures/sample returns the bundled
alerts unscored so the page can load them. The page's model checkbox is off.
It sends llm_notes=true only when that box is checked, and only a configured
SOC_TRIAGE_LLM_PROVIDER can rewrite the note. The page does not collect an
API key. The process still binds 127.0.0.1 by default, still has no
authentication, and is still not a production SIEM.
""".strip()

_INDEX_PATH = Path(__file__).resolve().parent / "static" / "index.html"


class HealthResponse(BaseModel):
    """Liveness payload. Synthetic mode, no alert data."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ok"] = "ok"
    mode: Literal["synthetic"] = "synthetic"


class TriageItem(BaseModel):
    """One scored alert. Same fields as a ``soc-triage run --format json`` row."""

    model_config = ConfigDict(extra="forbid")

    id: str
    category: str
    source: str
    timestamp: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    needs_review: bool
    reasons: list[Reason] = Field(min_length=1)
    note: str = Field(min_length=1)
    note_source: Literal["rules", "llm"]


class SingleTriageResponse(BaseModel):
    """Triage of one alert, plus the synthetic-mode banner."""

    model_config = ConfigDict(extra="forbid")

    banner: str = Field(min_length=1)
    id: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    needs_review: bool
    reasons: list[Reason] = Field(min_length=1)
    note: str = Field(min_length=1)
    note_source: Literal["rules", "llm"]


class SeverityCounts(BaseModel):
    """How many ranked rows landed at each severity."""

    model_config = ConfigDict(extra="forbid")

    critical: int = Field(ge=0)
    high: int = Field(ge=0)
    medium: int = Field(ge=0)
    low: int = Field(ge=0)
    info: int = Field(ge=0)


class BatchTriageResponse(BaseModel):
    """Ranked triage list and severity counts."""

    model_config = ConfigDict(extra="forbid")

    banner: str = Field(min_length=1)
    mode: Literal["synthetic"] = "synthetic"
    count: int = Field(ge=0)
    severity_counts: SeverityCounts
    results: list[TriageItem]


class BodySizeLimit:
    """Reject HTTP bodies larger than ``max_bytes`` before the route runs."""

    def __init__(self, app, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        try:
            declared = _content_length(scope)
        except ValueError:
            await _send_json(send, 400, {"detail": "Invalid Content-Length"})
            return
        if declared is not None and declared > self.max_bytes:
            await _send_json(send, 413, _too_large(self.max_bytes))
            return

        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                break
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > self.max_bytes:
                await _send_json(send, 413, _too_large(self.max_bytes))
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        payload = b"".join(chunks)
        sent = False

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": payload, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


def create_app(*, llm_notes_default: bool = False) -> FastAPI:
    """Build the demo API. ``llm_notes_default`` mirrors ``serve --llm-notes``."""
    app = FastAPI(
        title="SOC Triage Agent",
        summary="Local demo that ranks synthetic SOC alerts.",
        description=_DESCRIPTION,
        version=__version__,
        debug=False,
    )
    app.state.llm_notes_default = bool(llm_notes_default)
    app.add_middleware(BodySizeLimit, max_bytes=MAX_BODY_BYTES)
    _register_handlers(app)
    _register_routes(app)
    return app


def _register_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def invalid_input(_request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": _validation_detail(exc)})

    @app.exception_handler(Exception)
    async def unhandled(_request: Request, exc: Exception) -> JSONResponse:
        if isinstance(exc, HTTPException):
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
        logger.exception("request failed")
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})


def _read_index() -> str:
    try:
        return _INDEX_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise HTTPException(status_code=500, detail="UI page is missing") from exc


def _register_routes(app: FastAPI) -> None:
    @app.get("/", response_class=HTMLResponse)
    def ui_index() -> HTMLResponse:
        """Serve the local demo page.

        One static HTML file. The page posts alert JSON to ``POST /triage/batch``.
        It does not authenticate the caller and it does not collect an API key.
        """
        return HTMLResponse(_read_index())

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        """Report that the local demo process is up."""
        return HealthResponse()

    @app.post(
        "/triage",
        response_model=SingleTriageResponse,
        responses={422: {"description": "Alert JSON failed validation"}},
    )
    def triage_one(alert: Alert, request: Request, llm_notes: bool = False) -> SingleTriageResponse:
        """Triage one alert.

        The body is one Alert object. ``llm_notes`` defaults to false.
        The response severity, confidence, needs_review, reasons, note,
        and note_source come from the same functions as ``soc-triage run``.
        """
        report = _triage([alert], llm_notes=_enabled(request, llm_notes))
        row = report.results[0]
        return SingleTriageResponse(
            banner=report.banner,
            id=row.id,
            severity=row.severity,
            confidence=row.confidence,
            needs_review=row.needs_review,
            reasons=list(row.reasons),
            note=row.note,
            note_source=row.note_source,
        )

    @app.post(
        "/triage/batch",
        response_model=BatchTriageResponse,
        responses={422: {"description": "Batch failed validation or exceeds 500 alerts"}},
    )
    def triage_batch(
        request: Request,
        alerts: Annotated[
            list[Alert],
            Body(min_length=1, max_length=MAX_BATCH_SIZE),
        ],
        llm_notes: bool = False,
    ) -> BatchTriageResponse:
        """Triage a list of alerts and return them ranked, with severity counts.

        The body is a JSON array of Alert objects, the same shape as a fixture
        file. At most 500 alerts. ``llm_notes`` defaults to false.
        """
        _reject_duplicates(alerts)
        return _batch(_triage(alerts, llm_notes=_enabled(request, llm_notes)))

    @app.get("/fixtures/sample", response_model=list[Alert])
    def fixtures_sample() -> list[Alert]:
        """Return the bundled synthetic alerts in ``fixtures/alerts``, unscored.

        The demo page loads this list and posts it to ``POST /triage/batch``.
        This route does not score and does not call a model.
        """
        try:
            return load_alerts(default_alerts_dir())
        except FixtureLoadError as exc:
            raise HTTPException(
                status_code=500,
                detail="Bundled fixtures could not be loaded",
            ) from exc

    @app.get("/fixtures/demo", response_model=BatchTriageResponse)
    def fixtures_demo(request: Request, llm_notes: bool = False) -> BatchTriageResponse:
        """Triage the bundled synthetic fixtures in ``fixtures/alerts``.

        Same ranking as ``soc-triage run fixtures/alerts``. ``llm_notes``
        defaults to false.
        """
        try:
            alerts = load_alerts(default_alerts_dir())
        except FixtureLoadError as exc:
            raise HTTPException(
                status_code=500,
                detail="Bundled fixtures could not be loaded",
            ) from exc
        return _batch(_triage(alerts, llm_notes=_enabled(request, llm_notes)))


def _enabled(request: Request, llm_notes: bool) -> bool:
    return bool(llm_notes or request.app.state.llm_notes_default)


def _triage(alerts: list[Alert], *, llm_notes: bool) -> TriageReport:
    client, warning = optional_note_client(llm_notes)
    if warning is not None:
        logger.warning("%s", warning)
    elif client is not None:
        logger.warning("%s", SYNTHETIC_SEND_NOTICE)

    def on_fallback(alert_id: str, reason: str) -> None:
        logger.warning("%s", fallback_message(alert_id, reason))

    return build_report(
        alerts,
        banner=safety_banner(),
        rewriter=client,
        on_fallback=on_fallback if client is not None else None,
    )


def _batch(report: TriageReport) -> BatchTriageResponse:
    counts = severity_counts(report.results)
    return BatchTriageResponse(
        banner=report.banner,
        mode="synthetic",
        count=report.count,
        severity_counts=SeverityCounts(**counts),
        results=[_item(row) for row in report.results],
    )


def _item(row: RankedAlert) -> TriageItem:
    payload = row.model_dump(mode="json")
    return TriageItem.model_validate(payload)


def _reject_duplicates(alerts: list[Alert]) -> None:
    seen: set[str] = set()
    for alert in alerts:
        if alert.id in seen:
            raise HTTPException(status_code=422, detail=f"Duplicate alert id {alert.id}")
        seen.add(alert.id)


def _validation_detail(exc: RequestValidationError) -> list[dict[str, object]]:
    details: list[dict[str, object]] = []
    for err in exc.errors():
        loc = err.get("loc", ())
        details.append(
            {
                "loc": [str(part) for part in loc],
                "msg": str(err.get("msg", "Invalid input")),
                "type": str(err.get("type", "value_error")),
            }
        )
    return details


def _content_length(scope) -> int | None:
    raw = None
    for key, value in scope.get("headers") or []:
        if key.lower() == b"content-length":
            raw = value
            break
    if raw is None:
        return None
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid content length") from exc
    if not text or text.strip() != text:
        raise ValueError("invalid content length")
    try:
        length = int(text)
    except ValueError as exc:
        raise ValueError("invalid content length") from exc
    if length < 0:
        raise ValueError("invalid content length")
    return length


def _too_large(limit: int) -> dict[str, str]:
    return {"detail": f"Request body exceeds {limit} bytes"}


async def _send_json(send, status: int, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


app = create_app()
