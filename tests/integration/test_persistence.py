"""Integration Test - Scenario 13: Database Persistence Across Restarts."""
import os
import tempfile
import unittest

from agent.config import Config
from agent.db import DatabaseManager
from agent.main import KothAgent
from simulator.mock_environment import (
    MockFileSystem,
    MockFirewallManager,
    MockGeminiEngine,
    MockMonitor,
    MockScoreboardServer,
    MockServiceHost,
)


class TestPersistenceIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_persistence.db")
        self.db = DatabaseManager(self.db_path)

        self.config = Config(
            gemini_api_key="mock_key",
            scoreboard_url="http://mock-scoreboard.local",
            own_services=["10.0.1.5:80:web-service"],
            target_hosts=["198.51.100.10"],
            db_path=self.db_path,
            dry_run=True,
        )

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_scenario_13_historical_actions_survive_restarts(self):
        """Scenario 13: Verify historical actions and telemetry persist across agent lifecycle restarts."""
        # 1. Instance 1 executes actions
        sb1 = MockScoreboardServer()
        sh1 = MockServiceHost()
        sh1.fail_service("10.0.1.5", 80)
        sb1.set_state("service_down")

        agent1 = KothAgent(
            config=self.config,
            db_manager=self.db,
            telemetry_poller=sb1,
            brain=MockGeminiEngine(),
            monitor=MockMonitor(sh1, MockFileSystem()),
            firewall=MockFirewallManager(dry_run=True),
            patcher=sh1,
            skip_validation=True,
        )

        rec1 = agent1.tick()
        self.assertTrue(rec1.success)
        self.assertEqual(len(agent1.action_log), 1)

        # 2. Simulate complete agent shutdown and restart (Instance 2 initialized with same DB)
        db2 = DatabaseManager(self.db_path)
        sb2 = MockScoreboardServer()
        sh2 = MockServiceHost()

        agent2 = KothAgent(
            config=self.config,
            db_manager=db2,
            telemetry_poller=sb2,
            brain=MockGeminiEngine(),
            monitor=MockMonitor(sh2, MockFileSystem()),
            firewall=MockFirewallManager(dry_run=True),
            patcher=sh2,
            skip_validation=True,
        )

        # 3. Verify: Preloaded actions reflect history from previous session
        self.assertEqual(len(agent2.action_log), 1)
        self.assertIn("defend:10.0.1.5:80", agent2.action_log[0])

        # 4. Verify DB records and empirical success statistics
        recent = db2.get_recent_actions(limit=10)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["action_type"], "defend")
        self.assertEqual(recent[0]["target"], "10.0.1.5:80")
        self.assertTrue(recent[0]["empirical_success"])

        stats = db2.get_empirical_success_stats()
        self.assertEqual(stats["total"], 1)
        self.assertEqual(stats["successful"], 1)
        self.assertEqual(stats["rate"], 1.0)


if __name__ == "__main__":
    unittest.main()
