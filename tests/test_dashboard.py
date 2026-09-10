"""Unit tests for the Flask web dashboard and API endpoints."""
import os
import tempfile
import unittest

from agent.dashboard import create_app
from agent.db import DatabaseManager
from agent.telemetry import ServiceStatus, Telemetry


class TestDashboard(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "dash_test.db")
        self.db = DatabaseManager(db_path=self.db_path)
        self.app = create_app(db_manager=self.db)
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_index_page(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"KOTH Agent Tactical Console", resp.data)

    def test_api_status_empty_db(self):
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("telemetry", data)
        self.assertIn("recent_actions", data)
        self.assertIn("config", data)
        self.assertEqual(data["recent_actions"], [])
        self.assertEqual(data["telemetry"]["our_score"], 0.0)

    def test_api_status_with_data(self):
        tel = Telemetry(
            timestamp=1700000000.0,
            our_score=1250.0,
            rank=1,
            our_services=[
                ServiceStatus(host="10.0.0.10", port=80, up=True, last_checked=1700000000.0, note="Healthy")
            ],
            competitor_scores={"OpponentA": 900.0},
        )
        self.db.record_telemetry(tel)
        self.db.record_action(
            action_type="defend",
            target="10.0.0.10:80",
            priority="high",
            reasoning="Firewall rate limit",
        )

        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()

        self.assertEqual(data["telemetry"]["our_score"], 1250.0)
        self.assertEqual(data["telemetry"]["rank"], 1)
        self.assertEqual(len(data["telemetry"]["our_services"]), 1)
        self.assertEqual(data["telemetry"]["our_services"][0]["host"], "10.0.0.10")
        self.assertEqual(data["telemetry"]["our_services"][0]["port"], 80)
        self.assertTrue(data["telemetry"]["our_services"][0]["up"])

        self.assertEqual(len(data["recent_actions"]), 1)
        self.assertEqual(data["recent_actions"][0]["action_type"], "defend")
        self.assertEqual(data["recent_actions"][0]["target"], "10.0.0.10:80")
        self.assertEqual(data["recent_actions"][0]["priority"], "high")


if __name__ == "__main__":
    unittest.main()
