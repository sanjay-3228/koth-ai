"""Integration Test - Scenario 2: File Integrity Event & Defensive Policy."""
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


class TestFileIntegrityIntegration(unittest.TestCase):
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

    def test_file_tampering_triggers_defensive_policy(self):
        """Simulate file tampering on /var/www/html/index.php and verify defensive policy."""
        # 1. Simulate tampering
        tampered_path = "/var/www/html/index.php"
        self.file_system.tamper(tampered_path)
        self.assertIn(tampered_path, self.file_system.get_tampered_files())

        # 2. Agent tick
        record = self.agent.tick()

        # 3. Verify: Local policy was selected deterministically
        self.assertEqual(record.model_used, "local-policy")
        self.assertEqual(record.action_type, "defend")
        self.assertIn("10.0.1.5", record.target)

        # 4. Verify: Defensive action executed and verified
        self.assertTrue(record.success)
        self.assertTrue(record.empirical_success)
        self.assertIsNotNone(record.verification_result)


if __name__ == "__main__":
    unittest.main()
