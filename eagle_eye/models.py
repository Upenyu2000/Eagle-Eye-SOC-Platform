from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

SEVERITY_ORDER = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(slots=True)
class Finding:
    module: str
    title: str
    severity: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AnalysisResult:
    module: str
    summary: dict[str, Any]
    findings: list[Finding]
    records: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class Incident:
    module: str
    title: str
    severity: str
    description: str
    status: str = "Open"
    evidence: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
