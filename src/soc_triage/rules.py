"""Deterministic severity scoring.

Pure rules. No network calls and no API keys. Severity is never taken from a
language model.

Each alert starts at a category baseline. IOC reputation and count thresholds
can raise it. Incomplete context is capped at ``low`` and marked
``needs_review`` instead of guessing critical. An allowlist hit downgrades the
result to ``info`` unless a malicious IOC conflicts with it.

The labels in ``fixtures/labels.json`` match this function. There are no
intentional mismatches.

Thresholds (v1):

| Category | Raise / lower |
| --- | --- |
| brute_force | success after >= 10 failures → critical; >= 30 failures → high; >= 8 → medium; else low |
| phishing_url | malicious and clicked → critical; other malicious → high; suspicious → medium; unknown → low |
| malware_hash | malicious, executed, not quarantined → critical; other malicious → high; other known hash → medium |
| lateral_movement | malicious and spread >= 5 → critical; spread >= 5 → high; any single hop → medium |
| policy_noise | ``policy_violation`` → medium; otherwise info |
"""

from __future__ import annotations

from soc_triage.models import Alert, IocReputation, IocType, Reason, Severity, TriageResult

_SCALE: tuple[Severity, ...] = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)

_BASELINE: dict[str, Severity] = {
    "brute_force": Severity.MEDIUM,
    "phishing_url": Severity.MEDIUM,
    "malware_hash": Severity.MEDIUM,
    "lateral_movement": Severity.MEDIUM,
    "policy_noise": Severity.INFO,
}

_REP_RANK: dict[IocReputation, int] = {
    IocReputation.ALLOWLISTED: 1,
    IocReputation.UNKNOWN: 2,
    IocReputation.SUSPICIOUS: 3,
    IocReputation.MALICIOUS: 4,
}

_SPREAD_FIELDS: tuple[str, ...] = (
    "dest_host_count",
    "admin_share_connections",
    "remote_service_count",
    "file_copy_count",
    "remote_logon_count",
)

CONF_DECISIVE = 0.9
CONF_STRONG = 0.84
CONF_MODERATE = 0.75
CONF_CLEAR_LOW = 0.66
CONF_ALLOWLIST = 0.88
CONF_WEAK = 0.4


def score_alert(alert: Alert) -> TriageResult:
    """Score one alert. The same input always returns the same result."""
    reasons: list[Reason] = [
        Reason(
            code="category_baseline",
            message=(
                f"category {alert.category} baseline is {_BASELINE[alert.category].value}"
            ),
        )
    ]
    severity, confidence = _score_category(alert, reasons)
    severity, confidence = _apply_ioc_floor(alert, severity, confidence, reasons)
    incomplete = alert.raw_fields.get("context_complete") is False
    if incomplete:
        severity = Severity.LOW
        confidence = min(confidence, CONF_WEAK)
        reasons.append(
            Reason(
                code="incomplete_context",
                message=(
                    "raw_fields.context_complete=false; capped at low "
                    "instead of guessing a higher severity"
                ),
            )
        )
    severity, confidence = _apply_allowlist(alert, severity, confidence, reasons)
    if confidence < 0.5 and _SCALE.index(severity) >= _SCALE.index(Severity.HIGH):
        severity = Severity.LOW
        reasons.append(
            Reason(
                code="incomplete_context",
                message="confidence below 0.5; refused a critical or high severity",
            )
        )
    needs_review = confidence < 0.5 or incomplete
    return TriageResult(
        alert_id=alert.id,
        severity=severity,
        confidence=confidence,
        needs_review=needs_review,
        reasons=reasons,
    )


def _score_category(alert: Alert, reasons: list[Reason]) -> tuple[Severity, float]:
    if alert.category == "brute_force":
        return _score_brute_force(alert, reasons)
    if alert.category == "phishing_url":
        return _score_phishing(alert, reasons)
    if alert.category == "malware_hash":
        return _score_malware(alert, reasons)
    if alert.category == "lateral_movement":
        return _score_lateral(alert, reasons)
    return _score_policy(alert, reasons)


def _score_brute_force(alert: Alert, reasons: list[Reason]) -> tuple[Severity, float]:
    count = _raw_int(alert, "failure_count")
    if count is None:
        reasons.append(
            Reason(
                code="missing_field",
                message="raw_fields.failure_count is missing; not scoring a burst",
            )
        )
        return Severity.LOW, CONF_WEAK
    success = _raw_bool(alert, "success_after_failures")
    reasons.append(Reason(code="burst", message=f"raw_fields.failure_count={count}"))
    if success is True and count >= 10:
        reasons.append(
            Reason(
                code="burst",
                message=(
                    f"raw_fields.success_after_failures=true after {count} failures"
                ),
            )
        )
        return Severity.CRITICAL, CONF_DECISIVE
    if count >= 30:
        return Severity.HIGH, CONF_STRONG
    if count >= 8:
        return Severity.MEDIUM, CONF_MODERATE
    return Severity.LOW, CONF_CLEAR_LOW


def _score_phishing(alert: Alert, reasons: list[Reason]) -> tuple[Severity, float]:
    if not _has_url(alert):
        reasons.append(
            Reason(
                code="missing_field",
                message="no raw_fields.url and no url or domain IOC",
            )
        )
        return Severity.LOW, CONF_WEAK
    url = alert.raw_fields.get("url")
    if isinstance(url, str) and url:
        reasons.append(Reason(code="ioc_reputation", message=f"raw_fields.url={url}"))
    clicked = _raw_bool(alert, "clicked")
    rep = _strongest_reputation(alert)
    if rep is IocReputation.MALICIOUS and clicked is True:
        reasons.append(
            Reason(
                code="ioc_reputation",
                message="raw_fields.clicked=true and IOC reputation=malicious",
            )
        )
        return Severity.CRITICAL, CONF_DECISIVE
    if rep is IocReputation.MALICIOUS:
        return Severity.HIGH, CONF_STRONG
    if rep is IocReputation.SUSPICIOUS or (clicked is True and rep is not IocReputation.ALLOWLISTED):
        return Severity.MEDIUM, CONF_MODERATE
    if rep is IocReputation.ALLOWLISTED:
        return Severity.INFO, CONF_ALLOWLIST
    return Severity.LOW, CONF_CLEAR_LOW


def _score_malware(alert: Alert, reasons: list[Reason]) -> tuple[Severity, float]:
    digest = _hash_value(alert)
    if digest is None:
        reasons.append(
            Reason(
                code="missing_field",
                message="raw_fields.sha256 and sha256 IOCs are missing",
            )
        )
        return Severity.LOW, CONF_WEAK
    rep = _strongest_reputation(alert)
    executed = _raw_bool(alert, "executed")
    quarantined = _raw_bool(alert, "quarantined")
    reasons.append(
        Reason(
            code="ioc_reputation",
            message=(
                f"sha256 {digest} reputation={rep.value if rep else 'unset'} "
                f"raw_fields.executed={executed} raw_fields.quarantined={quarantined}"
            ),
        )
    )
    if (
        rep is IocReputation.MALICIOUS
        and executed is True
        and quarantined is not True
    ):
        return Severity.CRITICAL, CONF_DECISIVE
    if rep is IocReputation.MALICIOUS:
        return Severity.HIGH, CONF_STRONG
    if rep is IocReputation.ALLOWLISTED:
        return Severity.INFO, CONF_ALLOWLIST
    return Severity.MEDIUM, CONF_MODERATE


def _score_lateral(alert: Alert, reasons: list[Reason]) -> tuple[Severity, float]:
    counts = {name: _raw_int(alert, name) for name in _SPREAD_FIELDS}
    if all(value is None for value in counts.values()):
        reasons.append(
            Reason(
                code="missing_field",
                message="lateral spread fields are missing; not scoring a burst",
            )
        )
        return Severity.LOW, CONF_WEAK
    spread = max(value or 0 for value in counts.values())
    cited = ", ".join(f"raw_fields.{name}={value}" for name, value in counts.items())
    reasons.append(Reason(code="burst", message=f"spread={spread}; {cited}"))
    if _strongest_reputation(alert) is IocReputation.MALICIOUS and spread >= 5:
        return Severity.CRITICAL, CONF_DECISIVE
    if spread >= 5:
        return Severity.HIGH, CONF_STRONG
    if spread >= 1:
        return Severity.MEDIUM, CONF_MODERATE
    return Severity.LOW, CONF_CLEAR_LOW


def _score_policy(alert: Alert, reasons: list[Reason]) -> tuple[Severity, float]:
    count = _raw_int(alert, "event_count")
    if count is not None and count >= 50:
        reasons.append(
            Reason(
                code="burst",
                message=(
                    f"raw_fields.event_count={count}; policy_noise does not "
                    "raise severity on volume alone"
                ),
            )
        )
    if _raw_bool(alert, "policy_violation") is True:
        reasons.append(
            Reason(
                code="category_baseline",
                message="raw_fields.policy_violation=true",
            )
        )
        return Severity.MEDIUM, CONF_MODERATE
    return Severity.INFO, CONF_MODERATE


def _apply_ioc_floor(
    alert: Alert,
    severity: Severity,
    confidence: float,
    reasons: list[Reason],
) -> tuple[Severity, float]:
    reasons.append(Reason(code="ioc_reputation", message=_ioc_summary(alert)))
    if confidence <= CONF_WEAK:
        return severity, confidence
    reputation = _strongest_reputation(alert)
    if reputation is IocReputation.MALICIOUS and _SCALE.index(severity) < _SCALE.index(Severity.HIGH):
        return Severity.HIGH, max(confidence, CONF_STRONG)
    if reputation is IocReputation.SUSPICIOUS and severity is Severity.LOW:
        return Severity.MEDIUM, max(confidence, CONF_MODERATE)
    return severity, confidence


def _apply_allowlist(
    alert: Alert,
    severity: Severity,
    confidence: float,
    reasons: list[Reason],
) -> tuple[Severity, float]:
    if not _is_allowlisted(alert):
        return severity, confidence
    name = alert.raw_fields.get("allowlist_name")
    name_text = name if isinstance(name, str) and name else "unnamed"
    if alert.raw_fields.get("allowlisted") is True:
        detail = f"raw_fields.allowlisted=true allowlist_name={name_text}"
    else:
        detail = "an IOC reputation is allowlisted"
    if _has_malicious(alert):
        lowered = _at_most(_downgrade(severity), Severity.MEDIUM)
        reasons.append(
            Reason(
                code="allowlist",
                message=(
                    f"{detail} conflicts with a malicious IOC; "
                    "severity capped for human review"
                ),
            )
        )
        return lowered, CONF_WEAK
    reasons.append(
        Reason(
            code="allowlist",
            message=f"{detail}; downgraded to info as expected activity",
        )
    )
    return Severity.INFO, CONF_ALLOWLIST


def _is_allowlisted(alert: Alert) -> bool:
    if alert.raw_fields.get("allowlisted") is True:
        return True
    return any(ioc.reputation is IocReputation.ALLOWLISTED for ioc in alert.iocs)


def _has_malicious(alert: Alert) -> bool:
    return any(ioc.reputation is IocReputation.MALICIOUS for ioc in alert.iocs)


def _strongest_reputation(alert: Alert) -> IocReputation | None:
    reputations = [ioc.reputation for ioc in alert.iocs if ioc.reputation is not None]
    if not reputations:
        return None
    return max(reputations, key=lambda reputation: _REP_RANK[reputation])


def _ioc_summary(alert: Alert) -> str:
    if not alert.iocs:
        return "no IOCs on the alert"
    parts: list[str] = []
    for ioc in alert.iocs:
        reputation = ioc.reputation.value if ioc.reputation else "unset"
        parts.append(f"iocs {ioc.type.value} {ioc.value} reputation={reputation}")
    return "; ".join(parts)


def _has_url(alert: Alert) -> bool:
    url = alert.raw_fields.get("url")
    if isinstance(url, str) and url:
        return True
    return any(ioc.type in {IocType.URL, IocType.DOMAIN} for ioc in alert.iocs)


def _hash_value(alert: Alert) -> str | None:
    raw = alert.raw_fields.get("sha256")
    if isinstance(raw, str) and raw:
        return raw
    for ioc in alert.iocs:
        if ioc.type is IocType.SHA256:
            return ioc.value
    return None


def _raw_int(alert: Alert, key: str) -> int | None:
    value = alert.raw_fields.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _raw_bool(alert: Alert, key: str) -> bool | None:
    value = alert.raw_fields.get(key)
    if isinstance(value, bool):
        return value
    return None


def _downgrade(severity: Severity) -> Severity:
    index = _SCALE.index(severity)
    return _SCALE[max(0, index - 1)]


def _at_most(severity: Severity, ceiling: Severity) -> Severity:
    if _SCALE.index(severity) > _SCALE.index(ceiling):
        return ceiling
    return severity
