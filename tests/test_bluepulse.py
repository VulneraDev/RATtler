import os
import tempfile
import unittest
from pathlib import Path

from rattler.bluepulse import evaluate_bluepulse
from rattler.model import Check, Finding, Severity, Status


PROTECTION = [
    Check("gatekeeper", Status.HEALTHY, "enabled"),
    Check("xprotect", Status.HEALTHY, "installed"),
]
SENSORS = [
    Check("processes", Status.HEALTHY, "collected"),
    Check("persistence", Status.HEALTHY, "inspected"),
    Check("listeners", Status.HEALTHY, "inspected"),
    Check("loaded_images", Status.HEALTHY, "inspected"),
]


class BluePulseTests(unittest.TestCase):
    def test_no_available_sensors_has_low_confidence(self):
        pulse = evaluate_bluepulse([], [], [])
        self.assertEqual(pulse.status, Status.UNKNOWN)
        self.assertEqual(pulse.details["confidence"], "low")

    def test_healthy_snapshot_has_high_confidence(self):
        pulse = evaluate_bluepulse(PROTECTION, SENSORS, [])
        self.assertEqual(pulse.status, Status.HEALTHY)
        self.assertEqual(pulse.details["confidence"], "high")
        self.assertEqual(pulse.details["monitoring_mode"], "one-time snapshot")
        self.assertEqual(pulse.details["operational"], pulse.details["monitored"])

    def test_unknown_sensor_lowers_confidence_and_names_gap(self):
        sensors = SENSORS[:-1] + [Check("loaded_images", Status.UNKNOWN, "inventory unavailable")]
        pulse = evaluate_bluepulse(PROTECTION, sensors, [])
        self.assertEqual(pulse.status, Status.UNKNOWN)
        self.assertEqual(pulse.details["confidence"], "low")
        self.assertEqual(pulse.details["coverage_gaps"][0]["sensor"], "loaded_images")

    def test_not_applicable_sensor_does_not_create_a_gap(self):
        sensors = SENSORS + [Check("platform_feature", Status.UNKNOWN, "sensor is macOS-only")]
        pulse = evaluate_bluepulse(PROTECTION, sensors, [])
        self.assertEqual(pulse.status, Status.HEALTHY)
        self.assertEqual(pulse.details["coverage_gaps"], [])

    def test_native_drop_reduces_confidence(self):
        finding = Finding(
            "RAT-NATIVE-000", "Dropped", Severity.MEDIUM, "coverage", "gap", {"dropped": 7}
        )
        pulse = evaluate_bluepulse(PROTECTION, SENSORS, [finding])
        self.assertEqual(pulse.status, Status.DEGRADED)
        self.assertEqual(pulse.details["native_dropped_events"], 7)

    @unittest.skipIf(os.name == "nt", "POSIX permission check")
    def test_broad_state_permissions_reduce_confidence(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text("{}", encoding="utf-8")
            os.chmod(str(state), 0o644)
            pulse = evaluate_bluepulse(PROTECTION, SENSORS, [], state_path=state)
        self.assertEqual(pulse.status, Status.DEGRADED)
        self.assertEqual(pulse.details["artifact_issues"][0]["artifact"], "event state")
        self.assertIn("not private", pulse.details["artifact_issues"][0]["reason"])

    def test_ransomware_state_and_canary_are_assurance_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "ransomware-state.json"
            canary = Path(directory) / "ransomware-canary.txt"
            state.write_text("{}", encoding="utf-8")
            canary.write_text("canary", encoding="utf-8")
            if os.name != "nt":
                os.chmod(str(state), 0o600)
                os.chmod(str(canary), 0o600)
            pulse = evaluate_bluepulse(
                PROTECTION, SENSORS, [], ransomware_state_path=state,
            )
        self.assertEqual(pulse.status, Status.HEALTHY)
        self.assertEqual(pulse.details["artifacts_checked"], 2)


if __name__ == "__main__":
    unittest.main()
