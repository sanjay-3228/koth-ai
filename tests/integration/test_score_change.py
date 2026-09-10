"""Integration Test - Scenario 3: Score Change & Tactical Flash Routing."""
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


class TestScoreChangeIntegration(unittest.TestCase):
    def setUp(self):
        self.config = Config(
            gemini_api_key="mock_key",
            scoreboard_url="http://mock-scoreboard.local",
            own_services=["10.0.1.5:80:web-service", "10.0.1.5:22:sshd"],
            target_hosts=["198.51.100.10"],
            allowed_plugins=["test_exploit"],
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

        from agent.attack.plugin_interface import ExploitPlugin, ExploitResult
        from agent.attack.recon import HostFingerprint

        class MockReconScanner:
            def scan(self, host: str, ports: str = "1-1024"):
                return HostFingerprint(host=host, open_ports=[8080], services={8080: "http-alt"})

        self.agent.recon = MockReconScanner()
        self.agent.context.recon = self.agent.recon

        class MockExploitPlugin(ExploitPlugin):
            name = "test_exploit"
            matches_service = "http-alt"

            def run(self, host: str, port: int, context: dict) -> ExploitResult:
                return ExploitResult(success=True, notes="Simulated exploit success")

        self.agent.dispatcher.register(MockExploitPlugin())

    def test_score_change_triggers_flash_strategic_analysis(self):
        """Simulate score decrease and verify Flash analysis."""
        # 1. Simulate score decrease
        self.scoreboard.set_state("score_decrease")

        # 2. Agent tick
        record = self.agent.tick()

        # 3. Verify: Fast tactical model was chosen for strategic evaluation
        self.assertIn(record.model_used, (self.config.nvidia_fast_model, "nvidia/nemotron-3.5-lightning-30b-a3b"))
        self.assertTrue(record.success)
        self.assertTrue(record.empirical_success)

        # 4. Verify model call was made with telemetry summary containing rank & score
        self.assertGreater(len(self.gemini.call_history), 0)
        last_call = self.gemini.call_history[-1]
        self.assertIn(last_call["model"], (self.config.nvidia_fast_model, "nvidia/nemotron-3.5-lightning-30b-a3b"))
        self.assertIn("our_score=850.0", last_call["summary"])
        self.assertIn("rank=3", last_call["summary"])


if __name__ == "__main__":
    unittest.main()
