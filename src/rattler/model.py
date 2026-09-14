from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List


class Status(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


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
