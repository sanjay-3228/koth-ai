"""Unit tests for live authorized observation module, latency instrumentation, and reporting."""
import os
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from agent.config import Config
from agent.db import DatabaseManager
from agent.gemini_client import Decision
from agent.main import KothAgent
from agent.model_router import ModelRouter
from agent.observe import (
    ObservationCollector,
    calc_percentiles,
    generate_observation_report,
    observe_cycle,
)
from agent.scoreboard.base import NormalizedScoreboardState
from agent.telemetry import ServiceStatus, Telemetry, TelemetryPoller
from simulator.mock_environment import (
    MockFileSystem,
    MockGeminiEngine,
    MockMonitor,
    MockScoreboardServer,
    MockServiceHost,
)


class TestObservation(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_obs.db")
        self.db = DatabaseManager(db_path=self.db_path)
        self.config = Config(
            koth_mode="DRY_RUN",
            own_services=["10.0.1.5:80:web-service", "10.0.1.5:22:sshd"],
            target_hosts=["198.51.100.10"],
            allowed_plugins=["test_plugin"],
            scoreboard_url="http://mock-scoreboard.local/api",
            db_path=self.db_path,
        )
        self.config.dry_run = True

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_calc_percentiles_empty(self):
        stats = calc_percentiles([])
        self.assertEqual(stats["avg"], 0.0)
        self.assertEqual(stats["p50"], 0.0)
        self.assertEqual(stats["p95"], 0.0)
        self.assertEqual(stats["p99"], 0.0)

    def test_calc_percentiles_values(self):
        vals = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0]
        stats = calc_percentiles(vals)
        self.assertAlmostEqual(stats["avg"], 55.0, places=1)
        self.assertAlmostEqual(stats["p50"], 55.0, places=1)
        self.assertGreater(stats["p95"], 90.0)
        self.assertGreater(stats["p99"], 95.0)

    def test_observe_cycle_pipeline_and_sqlite(self):
        """Verify the complete pipeline executes and records to SQLite."""
        scoreboard = MockScoreboardServer()
        service_host = MockServiceHost()
        file_system = MockFileSystem()
        monitor = MockMonitor(service_host, file_system)
        brain = MockGeminiEngine()
        router = ModelRouter(db_manager=self.db)

        mock_provider = MagicMock()
        mock_provider.last_scoreboard_latency_ms = 12.5
        mock_provider.last_json_parsing_latency_ms = 0.8
        mock_provider.get_state.return_value = NormalizedScoreboardState(
            timestamp=time.time(),
            own_score=100.0,
            rank=1,
            is_valid=True,
            service_status=[ServiceStatus("10.0.1.5", 80, True, time.time())],
        )

        agent = KothAgent(
            config=self.config,
            db_manager=self.db,
            model_router=router,
            telemetry_poller=TelemetryPoller(provider=mock_provider),
            brain=brain,
            monitor=monitor,
            patcher=service_host,
            skip_validation=True,
        )

        collector = ObservationCollector()
        res = observe_cycle(agent, collector, probe_models=False)

        self.assertEqual(collector.total_cycles, 1)
        self.assertEqual(len(collector.scoreboard_latencies), 1)
        self.assertEqual(len(collector.telemetry_latencies), 1)
        self.assertEqual(len(collector.action_latencies), 1)
        self.assertEqual(len(collector.verification_latencies), 1)
        self.assertEqual(len(collector.end_to_end_latencies), 1)

        # Check DB recorded action with authorized and would_execute
        actions = self.db.get_recent_actions(limit=5)
        self.assertGreaterEqual(len(actions), 1)
        self.assertIn("authorized", actions[0])
        self.assertIn("would_execute", actions[0])
        self.assertTrue(actions[0]["authorized"])

        # Check model call was logged
        calls = self.db.get_recent_model_calls(limit=5)
        self.assertGreaterEqual(len(calls), 1)
        self.assertIn("model", calls[0])
        self.assertIn("latency_ms", calls[0])
        self.assertIn("success", calls[0])

    def test_stale_telemetry_triggers_safe_hold(self):
        """Verify stale scoreboard telemetry triggers SAFE HOLD."""
        mock_provider = MagicMock()
        mock_provider.last_scoreboard_latency_ms = 15.0
        mock_provider.last_json_parsing_latency_ms = 1.0
        mock_provider.get_state.return_value = NormalizedScoreboardState(
            timestamp=time.time() - 120.0,
            is_valid=False,
            is_stale=True,
            error="Scoreboard data is stale",
        )

        agent = KothAgent(
            config=self.config,
            db_manager=self.db,
            telemetry_poller=TelemetryPoller(provider=mock_provider),
            skip_validation=True,
        )

        collector = ObservationCollector()
        res = observe_cycle(agent, collector, probe_models=False)

        self.assertEqual(collector.stale_events, 1)
        self.assertEqual(res["decision"].action_type, "hold")
        self.assertEqual(res["record"].action_name, "hold")
        self.assertIn("stale", res["decision"].reasoning.lower())

    def test_generate_observation_report(self):
        """Verify generated markdown report includes all 13 required sections."""
        collector = ObservationCollector()
        collector.scoreboard_latencies.append(10.5)
        collector.json_parsing_latencies.append(0.5)
        collector.telemetry_latencies.append(15.2)
        collector.local_policy_latencies.append(0.2)
        collector.flash_latencies.append(120.0)
        collector.pro_latencies.append(350.0)
        collector.security_latencies.append(0.3)
        collector.queue_latencies.append(0.0)
        collector.action_latencies.append(2.1)
        collector.verification_latencies.append(1.5)
        collector.end_to_end_latencies.append(150.0)
        collector.total_cycles = 1
        collector.local_policy_decisions = 1
        collector.authorized_actions = 1
        collector.empirical_successes = 1

        agent = KothAgent(config=self.config, db_manager=self.db, skip_validation=True)
        report_file = os.path.join(self.tmp_dir.name, "test_observation_report.md")

        content = generate_observation_report(collector, agent, report_path=report_file)

        # Check file exists and has content
        self.assertTrue(os.path.isfile(report_file))

        # Check all 13 required sections
        required_sections = [
            "## 1. ENVIRONMENT",
            "## 2. SCOREBOARD",
            "## 3. TELEMETRY",
            "## 4. MODEL ROUTING",
            "## 5. REAL API LATENCY",
            "## 6. QUEUE LATENCY",
            "## 7. AUTHORIZATION",
            "## 8. VERIFICATION",
            "## 9. FAILURES",
            "## 10. FALLBACKS",
            "## 11. EMPIRICAL SUCCESS",
            "## 12. ANOMALIES",
            "## 13. SAFETY EVENTS",
            "STATUS: OBSERVATION_ONLY",
        ]
        for sec in required_sections:
            self.assertIn(sec, content, f"Missing section in report: {sec}")


if __name__ == "__main__":
    unittest.main()
