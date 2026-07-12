import unittest

from eagle_eye.services.automation import calculate_score, decide


class AutomationTests(unittest.TestCase):
    def test_scoring_and_decision(self):
        enrichments = [{"malicious": 2, "suspicious": 1, "found": True}]
        self.assertEqual(calculate_score(enrichments), 7)
        decision = decide(enrichments, case_threshold=6)
        self.assertEqual(decision.outcome, "create_case")

    def test_missing_reputation_is_not_malicious(self):
        decision = decide([{"found": False}], case_threshold=6)
        self.assertEqual(decision.score, 0)
        self.assertEqual(decision.outcome, "no_external_hit")


if __name__ == "__main__":
    unittest.main()
