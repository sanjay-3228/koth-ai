"""Integration Test - Scenario 14: Complete Competition Round Simulation."""
import unittest

from agent.config import Config
from simulator.metrics_collector import MetricsCollector
from simulator.timeline_engine import TimelineEngine


class TestCompetitionRoundIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_scenario_14_complete_deterministic_competition_round(self):
        """Scenario 14: Run full T+00 to T+25 deterministic competition timeline and verify behavior & latencies."""
        config = Config(
            gemini_api_key="mock_key",
            scoreboard_url="http://mock-scoreboard.local",
            own_services=["10.0.1.5:80:web-service", "10.0.1.5:443:nginx-ssl"],
            target_hosts=["198.51.100.10"],
            allowed_plugins=["test_exploit"],
            dry_run=True,
        )

        metrics = MetricsCollector()
        engine = TimelineEngine(config=config, metrics=metrics, time_step_delay=0.005)

        # Execute complete competition round
        result = await engine.run_round()

        # 1. Verify timeline completed all 26 steps (T=0 to T=25)
        self.assertEqual(result["timeline_steps"], 26)
        log = engine.timeline_log

        # Step T+00: healthy
        self.assertEqual(log[0]["second"], 0)

        # Step T+10: own web service fails -> local policy defend executed
        step10 = log[10]
        self.assertEqual(step10["second"], 10)
        self.assertEqual(step10["model_used"], "local-policy")
        self.assertEqual(step10["action_type"], "defend")
        self.assertTrue(step10["empirical_success"])

        # Step T+12: score decreases -> Fast tactical strategic analysis
        step12 = log[12]
        self.assertEqual(step12["second"], 12)
        self.assertIn(step12["model_used"], ("nvidia/nemotron-3.5-lightning-30b-a3b", "nvidia/nemotron-3.5-lightning-30b-a3b"))

        # Step T+16: second service fails -> multi-service down escalates to Reasoning
        step16 = log[16]
        self.assertEqual(step16["second"], 16)
        self.assertIn(step16["model_used"], (config.nvidia_reasoning_model, config.groq_reasoning_model, "gemini-3.1-pro-preview", "nvidia/nemotron-3-super-120b-a12b", "openai/gpt-oss-120b"))
        self.assertEqual(step16["action_type"], "defend")

        # Step T+17: integrity event -> local policy defensive rate limit
        step17 = log[17]
        self.assertEqual(step17["second"], 17)
        self.assertEqual(step17["model_used"], "local-policy")
        self.assertEqual(step17["action_type"], "defend")

        # Step T+20: Flash unavailable -> safe fallback
        step20 = log[20]
        self.assertEqual(step20["second"], 20)
        self.assertIn(step20["model_used"], ("local-policy", "safe-fallback"))

        # Step T+25: system recovered
        step25 = log[25]
        self.assertEqual(step25["second"], 25)

        # 2. Verify collected summary metrics
        summary = result["summary"]
        self.assertGreater(summary["local_policy_decisions"], 0)
        self.assertGreater(summary["flash_calls"], 0)
        self.assertGreater(summary["pro_calls"], 0)
        self.assertGreater(summary["successful_actions"], 0)
        self.assertGreater(summary["avg_decision_latency_ms"], 0.0)


if __name__ == "__main__":
    unittest.main()
