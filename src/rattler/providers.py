import json
import platform
import socket
from abc import ABC, abstractmethod
from typing import List, Optional

from .model import Check, Report, Status
from .runner import CommandResult, run


def _overall(checks: List[Check]) -> Status:
    states = {check.status for check in checks}
    if Status.UNHEALTHY in states:
        return Status.UNHEALTHY
    if Status.DEGRADED in states:
        return Status.DEGRADED
    if states and states == {Status.HEALTHY}:
        return Status.HEALTHY
    return Status.UNKNOWN


class Provider(ABC):
    name = "unknown"

    @abstractmethod
    def checks(self) -> List[Check]:
        raise NotImplementedError

    def report(self) -> Report:
        checks = self.checks()
        return Report(
            provider=self.name,
            hostname=socket.gethostname(),
            platform=platform.platform(),
            status=_overall(checks),
            checks=checks,
        )


class MacOSProvider(Provider):
    name = "macos-built-in"

    def checks(self) -> List[Check]:
        checks = [self._gatekeeper()]
        packages = (
            "com.apple.pkg.XProtectPlistConfigData",
            "com.apple.pkg.XProtectPayloads",
        )
        detected = 0
        for package in packages:
            result = run(["/usr/sbin/pkgutil", "--pkg-info", package])
            if result and result.returncode == 0:
                detected += 1
                version = self._field(result, "version") or "unknown"
                checks.append(Check(package, Status.HEALTHY, "installed", {"version": version}))
        if not detected:
            # Recent macOS releases may retain the bundle but not the historical
            # package receipts. Query one fixed, system-owned plist key.
            result = run([
                "/usr/libexec/PlistBuddy",
                "-c",
                "Print :CFBundleShortVersionString",
                "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
            ])
            if result and result.returncode == 0 and result.stdout:
                checks.append(Check("xprotect", Status.HEALTHY, "installed", {"version": result.stdout}))
            else:
                checks.append(Check("xprotect", Status.UNKNOWN, "XProtect metadata not found"))
        return checks

    @staticmethod
    def _field(result: CommandResult, key: str) -> Optional[str]:
        prefix = key + ":"
        for line in result.stdout.splitlines():
            if line.startswith(prefix):
                return line.split(":", 1)[1].strip()
        return None

    @staticmethod
    def _gatekeeper() -> Check:
        result = run(["/usr/sbin/spctl", "--status"])
        if result is None:
            return Check("gatekeeper", Status.UNKNOWN, "spctl unavailable")
        output = (result.stdout + " " + result.stderr).lower()
        enabled = result.returncode == 0 and "enabled" in output
        return Check(
            "gatekeeper",
            Status.HEALTHY if enabled else Status.UNHEALTHY,
            "enabled" if enabled else "disabled or unavailable",
        )


class WindowsDefenderProvider(Provider):
    name = "microsoft-defender"

    _SCRIPT = (
        "$ProgressPreference='SilentlyContinue';"
        "Get-MpComputerStatus | Select-Object AntivirusEnabled,"
        "RealTimeProtectionEnabled,AntivirusSignatureVersion,"
        "AntivirusSignatureLastUpdated | ConvertTo-Json -Compress"
    )

    def checks(self) -> List[Check]:
        result = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", self._SCRIPT])
        if result is None or result.returncode != 0:
            return [Check("defender", Status.UNKNOWN, "Defender status unavailable")]
        try:
            data = json.loads(result.stdout)
        except (TypeError, ValueError):
            return [Check("defender", Status.UNKNOWN, "Defender returned invalid status data")]
        antivirus = bool(data.get("AntivirusEnabled"))
        realtime = bool(data.get("RealTimeProtectionEnabled"))
        return [
            Check("antivirus", Status.HEALTHY if antivirus else Status.UNHEALTHY,
                  "enabled" if antivirus else "disabled"),
            Check("real_time_protection", Status.HEALTHY if realtime else Status.UNHEALTHY,
                  "enabled" if realtime else "disabled"),
            Check("signatures", Status.HEALTHY if data.get("AntivirusSignatureVersion") else Status.UNKNOWN,
                  "signature metadata reported" if data.get("AntivirusSignatureVersion") else "signature metadata unavailable",
                  {"version": data.get("AntivirusSignatureVersion"),
                   "last_updated": data.get("AntivirusSignatureLastUpdated")}),
        ]


class ClamAVProvider(Provider):
    name = "clamav"

    def checks(self) -> List[Check]:
        version = run(["clamscan", "--version"])
        if version is None or version.returncode != 0:
            return [Check("clamav", Status.UNKNOWN, "clamscan is not installed or not on PATH")]
        checks = [Check("engine", Status.HEALTHY, "ClamAV available", {"version": version.stdout})]
        daemon = run(["pgrep", "-x", "clamd"])
        if daemon is None:
            checks.append(Check("daemon", Status.UNKNOWN, "could not inspect clamd process"))
        elif daemon.returncode == 0:
            checks.append(Check("daemon", Status.HEALTHY, "clamd is running"))
        else:
            checks.append(Check("daemon", Status.DEGRADED, "clamd is not running"))
        return checks


def select_provider(system: Optional[str] = None) -> Provider:
    current = (system or platform.system()).lower()
    if current == "darwin":
        return MacOSProvider()
    if current == "windows":
        return WindowsDefenderProvider()
    return ClamAVProvider()
