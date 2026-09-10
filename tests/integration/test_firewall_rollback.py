"""Integration Test - Scenario 11: Firewall Failure & Transactional Rollback."""
import unittest

from agent.actions.defense_actions import BlockSourceAction
from agent.config import Config
from agent.main import KothAgent
from simulator.mock_environment import (
    MockFileSystem,
    MockFirewallManager,
    MockGeminiEngine,
    MockMonitor,
    MockScoreboardServer,
    MockServiceHost,
)


class TestFirewallRollbackIntegration(unittest.TestCase):
    def setUp(self):
        self.config = Config(
            gemini_api_key="mock_key",
            scoreboard_url="http://mock-scoreboard.local",
            own_services=["10.0.1.5:80:web-service"],
            target_hosts=["198.51.100.10"],
            dry_run=False,
        )
        self.scoreboard = MockScoreboardServer()
        self.service_host = MockServiceHost()
        self.file_system = MockFileSystem()
        self.monitor = MockMonitor(self.service_host, self.file_system)
        self.firewall = MockFirewallManager(dry_run=False)
        self.gemini = MockGeminiEngine()

        self.agent = KothAgent(
            config=self.config,
            telemetry_poller=self.scoreboard,
            brain=self.gemini,
            monitor=self.monitor,
            firewall=self.firewall,
            patcher=self.service_host,
            skip_validation=True,
        )

    def test_scenario_11_firewall_failure_triggers_automatic_rollback(self):
        """Scenario 11: When nft application fails, transaction automatically rolls back to backup."""
        # 1. Configure mock firewall to fail on next apply
        self.firewall.should_fail = True

        action = BlockSourceAction()
        record = action.execute("198.51.100.99", self.agent.context)

        # 2. Verify: Action failed and failure reason captured
        self.assertFalse(record.success)
        self.assertFalse(record.empirical_success)
        self.assertIn("Mock simulated kernel nftables error", record.failure_reason)

        # 3. Verify: Rollback restore was executed with the ruleset backup
        self.assertTrue(self.firewall.rollback_occurred)
        self.assertEqual(len(self.firewall.applied), 0)


if __name__ == "__main__":
    unittest.main()
