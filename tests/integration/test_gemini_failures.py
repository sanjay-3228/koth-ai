"""Integration Tests - Scenarios 6, 7, 8: Gemini Failures & Model Escalations."""
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


class TestGeminiFailuresIntegration(unittest.TestCase):
    def setUp(self):
        self.config = Config(
            gemini_api_key="mock_key",
            scoreboard_url="http://mock-scoreboard.local",
            own_services=["10.0.1.5:80:web-service", "10.0.1.5:22:sshd"],
            target_hosts=["198.51.100.10"],
            gemini_confidence_threshold=0.75,
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

        from agent.attack.recon import HostFingerprint
        class MockRecon:
            def scan(self, host: str, ports: str = "1-1024"):
                return HostFingerprint(host=host)
        self.agent.recon = MockRecon()
        self.agent.context.recon = self.agent.recon

    def test_scenario_6_flash_timeout_triggers_safe_fallback(self):
        """Scenario 6: Flash timeout/failure triggers safe fallback hold without crashing."""
        self.gemini.flash_available = False

        record = self.agent.tick()

        self.assertEqual(record.action_type, "hold")
        self.assertEqual(record.model_used, "safe-fallback")
        self.assertTrue(record.success)
        self.assertTrue(record.empirical_success)
        self.assertIn("Flash failed", self.agent.action_log[-1])

    def test_scenario_7_low_confidence_escalates_to_pro(self):
        """Scenario 7: Low confidence Flash decision (< 0.75) escalates to Gemini 3.1 Pro Preview."""
        self.gemini.force_low_confidence = True

        record = self.agent.tick()

        # Decision should have escalated to Reasoning / Pro Preview
        self.assertIn(record.model_used, (self.config.nvidia_reasoning_model, "gemini-3.1-pro-preview"))
        self.assertTrue(record.success)
        self.assertTrue(record.empirical_success)

        # Check call sequence: Fast first, then Reasoning
        calls = [c["model"] for c in self.gemini.call_history]
        self.assertIn(calls[0], (self.config.nvidia_fast_model, "nvidia/nemotron-3.5-lightning-30b-a3b"))
        self.assertIn(calls[1], (self.config.nvidia_reasoning_model, "gemini-3.1-pro-preview"))

    def test_scenario_8_pro_failure_falls_back_cleanly(self):
        """Scenario 8: Pro failure falls back cleanly to Flash or safe hold."""
        # Force high complexity (both services down) so router chooses Pro directly
        self.service_host.fail_service("10.0.1.5", 80)
        self.service_host.fail_service("10.0.1.5", 22)
        self.scoreboard.set_state("multiple_services_down")

        # Make Pro fail
        self.gemini.pro_available = False

        record = self.agent.tick()

        # Should fall back to Fast / Flash or safe hold without crashing
        self.assertIn(record.model_used, (self.config.nvidia_fast_model, "nvidia/nemotron-3.5-lightning-30b-a3b", "local-policy", "safe-fallback"))
        self.assertTrue(record.attempted)


if __name__ == "__main__":
    unittest.main()
