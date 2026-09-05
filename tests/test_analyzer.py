import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from analyzer import analyze_events


class AnalyzerTests(unittest.TestCase):
    def test_flags_ip_at_threshold(self):
        events = [{"timestamp": f"2026-01-01T00:00:0{i}Z", "username": "demo", "source_ip": "192.0.2.10", "status": "FAILED"} for i in range(5)]
        alerts = analyze_events(events, threshold=5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failed_attempts"], 5)
        self.assertEqual(alerts[0]["severity"], "medium")

    def test_success_after_failures_is_high_severity(self):
        events = [{"timestamp": f"2026-01-01T00:00:0{i}Z", "username": "demo", "source_ip": "192.0.2.20", "status": "FAILED"} for i in range(5)]
        events.append({"timestamp": "2026-01-01T00:00:10Z", "username": "demo", "source_ip": "192.0.2.20", "status": "SUCCESS"})
        alerts = analyze_events(events, threshold=5)
        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0]["success_after_failures"])
        self.assertEqual(alerts[0]["severity"], "high")

    def test_does_not_flag_below_threshold(self):
        events = [{"timestamp": f"2026-01-01T00:00:0{i}Z", "username": "demo", "source_ip": "192.0.2.30", "status": "FAILED"} for i in range(4)]
        self.assertEqual(analyze_events(events, threshold=5), [])


if __name__ == "__main__":
    unittest.main()
