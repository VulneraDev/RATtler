from .model import Assessment, BehaviorReport, Severity, Status
from .providers import Provider


SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def build_assessment(provider: Provider, behavior: BehaviorReport) -> Assessment:
    protection = provider.report()
    highest = max(
        [SEVERITY_RANK[item.severity] for item in behavior.findings]
        + [SEVERITY_RANK[item.severity] for item in behavior.events],
        default=0,
    )
    if highest >= SEVERITY_RANK[Severity.HIGH]:
        status = Status.UNHEALTHY
    elif highest:
        status = Status.DEGRADED
    elif protection.status == Status.UNHEALTHY:
        status = Status.UNHEALTHY
    elif protection.status in (Status.DEGRADED, Status.UNKNOWN):
        status = protection.status
    elif any(sensor.status == Status.UNKNOWN for sensor in behavior.sensors):
        status = Status.UNKNOWN
    else:
        status = Status.HEALTHY
    return Assessment(status=status, protection=protection, behavior=behavior)
