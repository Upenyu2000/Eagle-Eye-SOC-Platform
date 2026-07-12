import unittest
from pathlib import Path

from eagle_eye.services.phishing import analyse_message, defang


class PhishingTests(unittest.TestCase):
    def test_header_analysis_and_indicators(self):
        text = Path("demo/phishing_message.eml").read_text(encoding="utf-8")
        headers, body = text.split("\n\n", 1)
        result, indicators = analyse_message(headers, body)
        titles = {finding.title for finding in result.findings}
        self.assertIn("Reply-To domain differs from visible sender", titles)
        self.assertIn("Email authentication control failure", titles)
        self.assertTrue(any(item["type"] == "url" for item in indicators))
        self.assertEqual(result.summary["dmarc"], "fail")

    def test_defang(self):
        self.assertEqual(defang("https://example.com/a"), "hxxps://example[.]com/a")


if __name__ == "__main__":
    unittest.main()
