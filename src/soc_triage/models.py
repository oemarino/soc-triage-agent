"""Typed alert schema and triage results for synthetic SOC fixtures.

Spec fields: id, timestamp, source, category, raw fields, optional IOCs.
`TriageResult` is the rules-engine output (T3). Notes and reports come later.
"""

from __future__ import annotations

import ipaddress
import re
from enum import Enum
from typing import Any, Literal, Self
from urllib.parse import urlsplit

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"

CATEGORIES: tuple[str, ...] = (
    "brute_force",
    "phishing_url",
    "malware_hash",
    "lateral_movement",
    "policy_noise",
)

AlertCategory = Literal[
    "brute_force",
    "phishing_url",
    "malware_hash",
    "lateral_movement",
    "policy_noise",
]


class Severity(str, Enum):
    """Plan.md severity scale. The rules engine assigns these in T3."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IocType(str, Enum):
    IPV4 = "ipv4"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"


class IocReputation(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"
    ALLOWLISTED = "allowlisted"


class Ioc(BaseModel):
    """One indicator attached to an alert. The alert may omit indicators."""

    model_config = ConfigDict(extra="forbid")

    type: IocType
    value: str = Field(min_length=1, max_length=512)
    reputation: IocReputation | None = None

    @model_validator(mode="after")
    def value_matches_type(self) -> Self:
        if self.type is IocType.IPV4:
            try:
                ipaddress.IPv4Address(self.value)
            except ipaddress.AddressValueError as exc:
                raise ValueError(f"invalid ipv4 IOC: {self.value}") from exc
        elif self.type is IocType.SHA256 and re.fullmatch(r"[0-9a-f]{64}", self.value) is None:
            raise ValueError("sha256 IOC must be 64 lowercase hex characters")
        elif self.type is IocType.URL:
            parsed = urlsplit(self.value)
            if parsed.scheme != "https" or not parsed.hostname:
                raise ValueError("url IOC must be an https URL with a host")
        elif self.type is IocType.DOMAIN and (
            re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", self.value) is None
        ):
            raise ValueError("domain IOC must be a lowercase hostname")
        return self


class Alert(BaseModel):
    """One synthetic detection alert.

    ``raw_fields`` is free-form JSON. The bundled fixtures use ``allowlisted``,
    ``summary``, and category-specific counts. Those keys are conventions for
    later rules, not requirements of this schema.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=ID_PATTERN, description="Stable synthetic alert id.")
    timestamp: AwareDatetime = Field(description="When the alert was raised (timezone required).")
    source: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$",
        description="Demo sensor or product that raised the alert.",
    )
    category: AlertCategory
    raw_fields: dict[str, Any] = Field(description="Event fields a reviewer can cite.")
    iocs: list[Ioc] = Field(default_factory=list, description="Optional indicators.")


ReasonCode = Literal[
    "category_baseline",
    "burst",
    "ioc_reputation",
    "allowlist",
    "incomplete_context",
    "missing_field",
]


class Reason(BaseModel):
    """One checkable explanation for a triage score."""

    model_config = ConfigDict(extra="forbid")

    code: ReasonCode
    message: str = Field(min_length=1)


class TriageResult(BaseModel):
    """Severity from the rules engine. A human still makes the final call."""

    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(pattern=ID_PATTERN)
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    needs_review: bool
    reasons: list[Reason] = Field(min_length=1)

    @model_validator(mode="after")
    def low_confidence_is_not_critical(self) -> Self:
        if self.severity is Severity.CRITICAL and self.confidence < 0.5:
            raise ValueError("critical severity requires confidence >= 0.5")
        return self


class Label(BaseModel):
    """Ground-truth severity for one alert id."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=ID_PATTERN)
    severity: Severity


class LabelSet(BaseModel):
    """Labeled subset stored in ``fixtures/labels.json`` or a held-out file."""

    model_config = ConfigDict(extra="forbid")

    version: int = Field(ge=1)
    dataset: str = Field(min_length=1)
    description: str = Field(min_length=1)
    provenance: str = Field(min_length=1)
    held_out: bool = False
    labels: list[Label]

    @model_validator(mode="after")
    def unique_ids(self) -> Self:
        ids = [label.id for label in self.labels]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate label ids")
        return self
