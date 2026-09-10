"""Integration Test - Scenario 4: Multiple Simultaneous Failures & Escalation."""
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


class TestMultipleFailuresIntegration(unittest.TestCase):
    def setUp(self):
        self.config = Config(
            gemini_api_key="mock_key",
            scoreboard_url="http://mock-scoreboard.local",
            own_services=["10.0.1.5:80:web-service", "10.0.1.5:443:nginx-ssl", "10.0.1.5:22:sshd"],
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

    def test_multiple_failures_escalates_to_pro_reasoning(self):
        """Simulate multiple services down simultaneously and verify Pro escalation."""
        # 1. Simulate both port 80 and port 443 failing
        self.service_host.fail_service("10.0.1.5", 80)
        self.service_host.fail_service("10.0.1.5", 443)
        self.scoreboard.set_state("multiple_services_down")

        # 2. Agent tick
        record = self.agent.tick()

        # 3. Verify: In high-complexity multi-service failure, Reasoning model was selected
        self.assertIn(record.model_used, (self.config.nvidia_reasoning_model, "gemini-3.1-pro-preview"))
        self.assertEqual(record.action_type, "defend")
        self.assertEqual(record.target, "10.0.1.5:80")
        self.assertTrue(record.success)
        self.assertTrue(record.empirical_success)

        # 4. Verify call history reflects Reasoning model selection
        pro_calls = [c for c in self.gemini.call_history if any(k in c["model"].lower() for k in ("pro", "super", "120b", "reasoning"))]
        self.assertGreater(len(pro_calls), 0)


if __name__ == "__main__":
    unittest.main()
