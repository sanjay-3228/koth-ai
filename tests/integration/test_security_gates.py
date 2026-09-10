"""Integration Tests - Scenarios 9 & 10: Unauthorized Target & Service Security Gates."""
import unittest

from agent.config import Config
from agent.gemini_client import Decision
from agent.main import KothAgent
from simulator.mock_environment import (
    MockFileSystem,
    MockFirewallManager,
    MockGeminiEngine,
    MockMonitor,
    MockScoreboardServer,
    MockServiceHost,
)


class TestSecurityGatesIntegration(unittest.TestCase):
    def setUp(self):
        self.config = Config(
            gemini_api_key="mock_key",
            scoreboard_url="http://mock-scoreboard.local",
            own_services=["10.0.1.5:80:web-service", "10.0.1.5:22:sshd"],
            target_hosts=["198.51.100.10"],
            dry_run=True,
        )
        self.scoreboard = MockScoreboardServer()
        self.service_host = MockServiceHost()
        self.file_system = MockFileSystem()
        self.monitor = MockMonitor(self.service_host, self.file_system)
        self.firewall = MockFirewallManager(dry_run=True)
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

    def test_scenario_9_unauthorized_target_rejected_by_security_policy(self):
        """Scenario 9: When AI suggests an unauthorized target (e.g. 8.8.8.8), SecurityPolicy blocks it."""
        # Program Gemini to output an out-of-scope target
        self.gemini.custom_response = Decision(
            action_type="attack",
            target="8.8.8.8:53",
            priority="high",
            reasoning="Attempting unauthorized out-of-scope attack",
        )

        record = self.agent.tick()

        # Action should have been intercepted and reverted to safe hold
        self.assertEqual(record.action_type, "hold")
        self.assertEqual(record.action_name, "hold")
        self.assertTrue(record.success)
        self.assertTrue(record.empirical_success)
        self.assertIn("Security Policy Rejection", self.agent.action_log[-1])

    def test_scenario_10_unauthorized_service_unit_cannot_execute(self):
        """Scenario 10: When AI attempts to defend unconfigured service or arbitrary unit, execution is aborted."""
        # Program Gemini to output an unconfigured host
        self.gemini.custom_response = Decision(
            action_type="defend",
            target="10.0.99.99:9999",
            priority="critical",
            reasoning="Attempting to restart arbitrary unconfigured service",
        )

        record = self.agent.tick()

        # Security gate must reject defending unconfigured host
        self.assertEqual(record.action_type, "hold")
        self.assertEqual(record.action_name, "hold")
        self.assertIn("not in configured OWN_SERVICES", self.agent.action_log[-1])
        # Verify no service was restarted
        self.assertEqual(self.service_host.services["web-service"]["restarted_count"], 0)


if __name__ == "__main__":
    unittest.main()
