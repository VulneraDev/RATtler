"""Read-only behavioral sensors for common RAT footholds.

These rules intentionally report explainable indicators rather than claiming a
process is malicious. They never inspect file contents beyond launchd plists and
never terminate, quarantine, or modify endpoint state.
"""

import os
import platform
import plistlib
import posixpath
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .model import BehaviorReport, Check, Finding, Severity, Status
from .runner import run


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    ppid: int
    executable: str


def _under(path: str, root: str) -> bool:
    try:
        normalized_path = posixpath.normpath(posixpath.abspath(path))
        normalized_root = posixpath.normpath(posixpath.abspath(root))
        return posixpath.commonpath((normalized_path, normalized_root)) == normalized_root
    except ValueError:
        return False


def suspicious_location(path: str, home: Optional[str] = None) -> Optional[str]:
    """Return a human-readable reason when an executable uses a risky location."""
    if not path or not posixpath.isabs(path):
        return None
    user_home = home or str(Path.home())
    roots = (
        ("/tmp", "temporary directory"),
        ("/private/tmp", "temporary directory"),
        ("/var/tmp", "temporary directory"),
        (posixpath.join(user_home, "Downloads"), "Downloads directory"),
        (posixpath.join(user_home, ".cache"), "user cache directory"),
    )
    for root, reason in roots:
        if _under(path, root):
            return reason
    real_path = posixpath.normpath(posixpath.abspath(path))
    if real_path.startswith(("/private/var/folders/", "/var/folders/")) and "/T/" in real_path:
        return "per-user temporary directory"
    if path.endswith(" (deleted)"):
        return "deleted executable image"
    return None


def trusted_system_location(path: str) -> bool:
    """Return whether macOS protects the executable's system-owned location."""
    if platform.system() != "Darwin" or not path:
        return False
    return any(_under(path, root) for root in (
        "/System/Library", "/usr/bin", "/usr/libexec", "/bin", "/sbin"
    ))


def parse_processes(output: str) -> List[ProcessInfo]:
    processes = []
    for line in output.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) != 3:
            continue
        try:
            processes.append(ProcessInfo(int(parts[0]), int(parts[1]), parts[2]))
        except ValueError:
            continue
    return processes


def process_sensor(home: Optional[str] = None) -> Tuple[Check, List[Finding], Dict[int, ProcessInfo]]:
    command = ["/bin/ps", "-axo", "pid=,ppid=,comm="] if platform.system() == "Darwin" else ["ps", "-axo", "pid=,ppid=,comm="]
    result = run(command)
    if result is None or result.returncode != 0:
        return Check("processes", Status.UNKNOWN, "process inventory unavailable"), [], {}
    processes = parse_processes(result.stdout)
    findings = []
    for process in processes:
        reason = suspicious_location(process.executable, home)
        if reason:
            findings.append(Finding(
                "RAT-PROC-001",
                "Process launched from a risky location",
                Severity.HIGH if "temporary" in reason or "deleted" in reason else Severity.MEDIUM,
                "process",
                "A running executable originates from a location frequently abused by droppers.",
                {"pid": process.pid, "ppid": process.ppid, "executable": process.executable, "reason": reason},
            ))
    return (
        Check("processes", Status.HEALTHY, "process inventory collected", {"count": len(processes)}),
        findings,
        {process.pid: process for process in processes},
    )


def _program_from_plist(data: Dict[str, object]) -> Optional[str]:
    program = data.get("Program")
    if isinstance(program, str) and program:
        return program
    arguments = data.get("ProgramArguments")
    if isinstance(arguments, list) and arguments and isinstance(arguments[0], str):
        return arguments[0]
    return None


def inspect_launchd_file(path: Path, home: Optional[str] = None) -> List[Finding]:
    findings = []
    try:
        if path.is_symlink():
            findings.append(Finding(
                "RAT-PERSIST-001", "Symlinked launchd entry", Severity.MEDIUM, "persistence",
                "A launchd plist is a symbolic link, which can obscure its real location.",
                {"plist": str(path)},
            ))
        if path.stat().st_size > 2 * 1024 * 1024:
            return findings + [Finding(
                "RAT-PERSIST-002", "Oversized launchd entry", Severity.MEDIUM, "persistence",
                "The launchd plist is unexpectedly large and was not parsed.", {"plist": str(path)},
            )]
        with path.open("rb") as handle:
            data = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException, ValueError, TypeError):
        return findings + [Finding(
            "RAT-PERSIST-003", "Unreadable launchd entry", Severity.LOW, "persistence",
            "A launchd plist could not be safely parsed.", {"plist": str(path)},
        )]
    if not isinstance(data, dict):
        return findings
    label = data.get("Label") if isinstance(data.get("Label"), str) else path.stem
    environment = data.get("EnvironmentVariables", {})
    if isinstance(environment, dict):
        injection_keys = sorted(set(environment).intersection({"DYLD_INSERT_LIBRARIES", "LD_PRELOAD"}))
        if injection_keys:
            findings.append(Finding(
                "RAT-INJECT-001", "Launch-time library injection configured", Severity.CRITICAL,
                "injection", "A persistence entry configures a library-preload environment variable.",
                {"plist": str(path), "label": label, "variables": injection_keys},
            ))
    program = _program_from_plist(data)
    if not program:
        return findings
    if not os.path.isabs(program):
        findings.append(Finding(
            "RAT-PERSIST-004", "Relative executable in launchd entry", Severity.HIGH, "persistence",
            "A launchd entry uses a relative executable path.",
            {"plist": str(path), "label": label, "executable": program},
        ))
        return findings
    reason = suspicious_location(program, home)
    if reason:
        findings.append(Finding(
            "RAT-PERSIST-005", "Persistent executable in a risky location", Severity.HIGH,
            "persistence", "A launchd entry starts an executable from a user-writable staging location.",
            {"plist": str(path), "label": label, "executable": program, "reason": reason},
        ))
    try:
        mode = os.stat(program).st_mode
        if mode & stat.S_IWOTH:
            findings.append(Finding(
                "RAT-PERSIST-006", "World-writable persistent executable", Severity.HIGH,
                "persistence", "Any local user can replace the executable launched at startup.",
                {"plist": str(path), "label": label, "executable": program},
            ))
    except OSError:
        if not trusted_system_location(program):
            findings.append(Finding(
                "RAT-PERSIST-007", "Missing persistent executable", Severity.LOW, "persistence",
                "A launchd entry references an executable that is currently missing.",
                {"plist": str(path), "label": label, "executable": program},
            ))
    return findings


def persistence_sensor(paths: Optional[Sequence[Path]] = None, home: Optional[str] = None) -> Tuple[Check, List[Finding]]:
    if platform.system() != "Darwin" and paths is None:
        return Check("persistence", Status.UNKNOWN, "launchd sensor is macOS-only"), []
    roots = list(paths) if paths is not None else [
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
        Path(home or str(Path.home())) / "Library/LaunchAgents",
    ]
    files = []
    for root in roots:
        try:
            files.extend(sorted(root.glob("*.plist")))
        except OSError:
            continue
    findings = []
    for path in files:
        findings.extend(inspect_launchd_file(path, home))
    return Check("persistence", Status.HEALTHY, "launchd entries inspected", {"count": len(files)}), findings


def _parse_lsof(output: str) -> List[Tuple[int, str, str]]:
    listeners = []
    seen = set()
    pid = None
    command = "unknown"
    for line in output.splitlines():
        if line.startswith("p") and line[1:].isdigit():
            pid = int(line[1:])
            command = "unknown"
        elif line.startswith("c"):
            command = line[1:]
        elif line.startswith("n") and pid is not None:
            listener = (pid, command, line[1:])
            if listener not in seen:
                listeners.append(listener)
                seen.add(listener)
    return listeners


def network_sensor(processes: Dict[int, ProcessInfo], home: Optional[str] = None) -> Tuple[Check, List[Finding]]:
    lsof = "/usr/sbin/lsof" if platform.system() == "Darwin" else "lsof"
    result = run([lsof, "-nP", "-Fpcn", "-iTCP", "-sTCP:LISTEN"])
    if result is None or result.returncode not in (0, 1):
        return Check("listeners", Status.UNKNOWN, "TCP listener inventory unavailable"), []
    listeners = _parse_lsof(result.stdout)
    findings = []
    for pid, command, address in listeners:
        exposed = address.startswith("*:") or address.startswith("0.0.0.0:") or address.startswith("[::]:")
        if not exposed:
            continue
        process = processes.get(pid)
        executable = process.executable if process else None
        reason = suspicious_location(executable or "", home)
        if not reason and trusted_system_location(executable or ""):
            continue
        findings.append(Finding(
            "RAT-NET-001" if not reason else "RAT-NET-002",
            "Externally reachable TCP listener" if not reason else "Risky process exposes a TCP listener",
            Severity.LOW if not reason else Severity.HIGH,
            "network",
            "A process is listening on all network interfaces; verify that remote access is intended.",
            {"pid": pid, "process": command, "executable": executable, "listener": address},
        ))
    return Check("listeners", Status.HEALTHY, "TCP listeners inspected", {"count": len(listeners)}), findings


def scan_behavior(home: Optional[str] = None, persistence_paths: Optional[Sequence[Path]] = None) -> BehaviorReport:
    from .injection import loaded_image_sensor

    process_check, process_findings, processes = process_sensor(home)
    persistence_check, persistence_findings = persistence_sensor(persistence_paths, home)
    network_check, network_findings = network_sensor(processes, home)
    image_check, image_findings = loaded_image_sensor(processes, home)
    return BehaviorReport(
        sensors=[process_check, persistence_check, network_check, image_check],
        findings=process_findings + persistence_findings + network_findings + image_findings,
    )
