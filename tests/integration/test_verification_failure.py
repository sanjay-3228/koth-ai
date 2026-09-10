"""Integration Test - Scenario 12: Action Verification Failure & Empirical Mismatch."""
import unittest

from agent.actions.defense_actions import RestartServiceAction
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


class TestVerificationFailureIntegration(unittest.TestCase):
    def setUp(self):
        self.config = Config(
            gemini_api_key="mock_key",
            scoreboard_url="http://mock-scoreboard.local",
            own_services=["10.0.1.5:80:web-service"],
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

    def test_scenario_12_verification_failure_sets_empirical_success_false(self):
        """Scenario 12: When action reports success but port check fails, empirical_success must be False."""
        # 1. Configure the service host so systemctl restart succeeds, but the port remains unreachable
        self.service_host.fail_service("10.0.1.5", 80)
        self.service_host.services["web-service"]["verification_should_fail"] = True

        action = RestartServiceAction()
        record = action.execute("10.0.1.5:80", self.agent.context)

        # 2. Systemctl restart reported success
        self.assertTrue(record.success, "Service patcher should have reported success")

        # 3. Independent socket verification detected failure
        self.assertFalse(record.verification_result.get("verified_up"), "Port verification should have failed")

        # 4. CRITICAL: empirical_success MUST be False despite record.success being True
        self.assertFalse(record.empirical_success, "empirical_success must reflect reality, not self-reported success!")


if __name__ == "__main__":
    unittest.main()
