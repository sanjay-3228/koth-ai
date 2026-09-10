"""Integration Test - Scenario 1: Own Service Failure & Independent Verification."""
import unittest

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


class TestServiceFailureIntegration(unittest.TestCase):
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

    def test_service_failure_detection_and_recovery(self):
        """Simulate own web service (10.0.1.5:80) failure and verify automated recovery."""
        # 1. Simulate failure
        self.service_host.fail_service("10.0.1.5", 80)
        self.scoreboard.set_state("service_down")

        # Port must be down initially
        self.assertFalse(self.service_host.check_port("10.0.1.5", 80))

        # 2. Agent tick
        record = self.agent.tick()

        # 3. Verify: Local policy was selected deterministically (Gemini bypassed)
        self.assertEqual(record.model_used, "local-policy")
        self.assertEqual(record.action_type, "defend")
        self.assertEqual(record.target, "10.0.1.5:80")
        self.assertEqual(record.action_name, "restart_service")

        # 4. Verify: Configured recovery action executed on mapped unit 'web-service'
        self.assertEqual(self.service_host.services["web-service"]["restarted_count"], 1)

        # 5. Verify: Independent state verification confirms service is restored
        self.assertTrue(record.success)
        self.assertTrue(record.empirical_success)
        self.assertTrue(record.verification_result.get("verified_up"))
        self.assertTrue(self.service_host.check_port("10.0.1.5", 80))


if __name__ == "__main__":
    unittest.main()
