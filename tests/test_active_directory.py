import unittest
from pathlib import Path

from eagle_eye.services.active_directory import analyse_ad_records
from eagle_eye.services.common import load_records


class ActiveDirectoryTests(unittest.TestCase):
    def test_detects_core_ad_patterns(self):
        records = load_records(Path("demo/ad_events.json"))
        result = analyse_ad_records(records, ticket_burst_threshold=5, window_seconds=300)
        titles = {finding.title for finding in result.findings}
        self.assertIn("Kerberos service tickets used RC4 encryption", titles)
        self.assertIn("Burst of Kerberos service-ticket requests", titles)
        self.assertIn("Process accessed LSASS", titles)
        self.assertIn("Privileged NTLM network logon correlation", titles)


if __name__ == "__main__":
    unittest.main()
