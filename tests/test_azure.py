import unittest
from pathlib import Path

from eagle_eye.services.azure import analyse_azure_records, remediation_command
from eagle_eye.services.common import load_records


class AzureTests(unittest.TestCase):
    def test_detects_public_storage_changes(self):
        records = load_records(Path("demo/azure_activity.json"))
        result = analyse_azure_records(records)
        self.assertEqual(result.summary["public_access_changes"], 2)
        self.assertEqual(len(result.findings), 2)

    def test_remediation_command_is_argument_safe(self):
        command = remediation_command("rg-lab", "storage123", "sub-lab")
        self.assertEqual(command[0], "az")
        self.assertIn("--allow-blob-public-access", command)
        self.assertIn("false", command)
        self.assertIn("sub-lab", command)


if __name__ == "__main__":
    unittest.main()
