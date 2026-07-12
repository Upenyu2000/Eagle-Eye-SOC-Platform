import unittest
from pathlib import Path

from eagle_eye.services.common import load_records
from eagle_eye.services.siem import analyse_auth_records


class SiemTests(unittest.TestCase):
    def test_detects_repeated_failures_and_success(self):
        records = load_records(Path("demo/siem_events.json"))
        result = analyse_auth_records(records, failure_threshold=3, window_seconds=120)
        titles = {finding.title for finding in result.findings}
        self.assertIn("Repeated Windows authentication failures", titles)
        self.assertIn("Successful logon followed failed attempts", titles)
        self.assertEqual(result.summary["failed_logons"], 3)
        self.assertEqual(result.summary["successful_logons"], 2)


if __name__ == "__main__":
    unittest.main()
