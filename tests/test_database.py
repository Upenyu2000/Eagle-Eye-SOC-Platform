import tempfile
import unittest
from pathlib import Path

from eagle_eye.database import Database
from eagle_eye.models import Incident


class DatabaseTests(unittest.TestCase):
    def test_incident_lifecycle(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "test.db")
            incident_id = database.add_incident(
                Incident(
                    module="SIEM",
                    title="Test incident",
                    severity="high",
                    description="Synthetic test",
                )
            )
            self.assertGreater(incident_id, 0)
            self.assertEqual(database.dashboard_stats()["total"], 1)
            database.update_incident_status(incident_id, "Closed")
            self.assertEqual(database.dashboard_stats()["open"], 0)


if __name__ == "__main__":
    unittest.main()
