"""Unit tests for the SQLite persistence layer (agent.db)."""
import os
import tempfile
import unittest

from agent.db import DatabaseManager
from agent.telemetry import ServiceStatus, Telemetry


class TestDatabaseManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_koth.db")
        self.db = DatabaseManager(db_path=self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_record_and_get_telemetry(self):
        tel = Telemetry(
            timestamp=1700000000.0,
            our_score=450.5,
            rank=2,
            our_services=[
                ServiceStatus(host="10.0.1.5", port=80, up=True, last_checked=1700000000.0, note="ok"),
                ServiceStatus(host="10.0.1.5", port=22, up=False, last_checked=1700000000.0, note="down"),
            ],
            competitor_scores={"TeamAlpha": 520.0, "TeamBeta": 390.0},
            raw={"sample": "data"},
        )

        row_id = self.db.record_telemetry(tel)
        self.assertGreater(row_id, 0)

        latest = self.db.get_latest_telemetry()
        self.assertIsNotNone(latest)
        self.assertEqual(latest["our_score"], 450.5)
        self.assertEqual(latest["rank"], 2)
        self.assertEqual(len(latest["our_services"]), 2)
        self.assertTrue(latest["our_services"][0]["up"])
        self.assertFalse(latest["our_services"][1]["up"])
        self.assertEqual(latest["competitor_scores"]["TeamAlpha"], 520.0)

    def test_record_and_get_actions(self):
        self.db.record_action(
            action_type="recon",
            target="10.0.2.1",
            priority="medium",
            reasoning="Discover open ports",
            timestamp=100.0,
        )
        self.db.record_action(
            action_type="defend",
            target="10.0.1.5:80",
            priority="critical",
            reasoning="Service down",
            timestamp=200.0,
        )

        recent = self.db.get_recent_actions(limit=10)
        self.assertEqual(len(recent), 2)
        # Ordered newest first
        self.assertEqual(recent[0]["action_type"], "defend")
        self.assertEqual(recent[1]["action_type"], "recon")

        # Prompt strings should be formatted and in chronological order (oldest first)
        action_strings = self.db.get_recent_action_strings(limit=10)
        self.assertEqual(len(action_strings), 2)
        self.assertEqual(action_strings[0], "recon:10.0.2.1:Discover open ports")
        self.assertEqual(action_strings[1], "defend:10.0.1.5:80:Service down")

    def test_persistence_across_restarts(self):
        self.db.record_action(
            action_type="hold",
            target="",
            priority="low",
            reasoning="Holding baseline",
        )

        # Simulate agent restart by instantiating new DatabaseManager pointing to same file
        restarted_db = DatabaseManager(db_path=self.db_path)
        recent = restarted_db.get_recent_actions()
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["action_type"], "hold")
        self.assertEqual(recent[0]["reasoning"], "Holding baseline")


if __name__ == "__main__":
    unittest.main()
