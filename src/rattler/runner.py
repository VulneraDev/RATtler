import subprocess
from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def run(command: Iterable[str], timeout: float = 10.0) -> Optional[CommandResult]:
    """Run a fixed argv command without a shell; return None if unavailable/timed out."""
    try:
        completed = subprocess.run(
            list(command),
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    return CommandResult(completed.returncode, completed.stdout.strip(), completed.stderr.strip())
