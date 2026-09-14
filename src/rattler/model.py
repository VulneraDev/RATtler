from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List


class Status(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Check:
    name: str
    status: Status
    message: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Report:
    provider: str
    hostname: str
    platform: str
    status: Status
    checks: List[Check]
    observed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    message: str
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BehaviorReport:
    sensors: List[Check]
    findings: List[Finding]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Assessment:
    status: Status
    protection: Report
    behavior: BehaviorReport
    observed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
