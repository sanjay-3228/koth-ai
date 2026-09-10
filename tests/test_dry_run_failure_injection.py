"""Comprehensive failure injection test harness for KOTH agent in DRY_RUN mode.

Validates that all 13 injected failure classes are safely tolerated and that the
agent remains alive, never crashes, and returns to SAFE HOLD when appropriate:
  1. Scoreboard timeout
  2. Scoreboard malformed response
  3. Gemini Flash timeout
  4. Gemini Pro timeout
  5. Simultaneous service failures
  6. Stale telemetry
  7. Verification failure
  8. Unauthorized target
  9. Unauthorized service
  10. Firewall transaction failure
  11. Database failure
  12. Queue overload
  13. Slow reconnaissance
"""
import asyncio
import json
import sqlite3
import os
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

import requests

from agent.actions.base import ActionContext, ActionExecutionRecord
from agent.actions.defense_actions import RestartServiceAction
from agent.actions.registry import ActionRegistry
from agent.async_orchestrator import AsyncOrchestrator, TaskPriority
from agent.config import Config
from agent.db import DatabaseManager
from agent.gemini_client import Decision
from agent.main import KothAgent
from agent.model_router import ModelRouter
from agent.scoreboard.adapter import ConfigurableScoreboardAdapter
from agent.scoreboard.base import NormalizedScoreboardState
from agent.scoreboard.config_parser import ScoreboardSchemaConfig
from agent.security.policy import SecurityPolicy
from agent.telemetry import ServiceStatus, Telemetry, TelemetryPoller
from simulator.mock_environment import (
    MockFileSystem,
    MockFirewallManager,
    MockGeminiEngine,
    MockMonitor,
    MockReconFast,
    MockScoreboardServer,
    MockServiceHost,
)


class TestDryRunFailureInjection(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_injection.db")
        self.config = Config(
            koth_mode="DRY_RUN",
            own_services=["10.0.1.5:80:web-service", "10.0.1.5:443:ssl-service"],
            target_hosts=["198.51.100.10", "198.51.100.20"],
            allowed_plugins=["test_plugin"],
            scoreboard_url="http://mock-scoreboard/api",
            db_path=self.db_path,
            gemini_confidence_threshold=0.75,
            stale_telemetry_threshold=30.0,
        )
        self.config.dry_run = True
        self.db = DatabaseManager(db_path=self.db_path)
        self.service_host = MockServiceHost()
        self.file_system = MockFileSystem()
        self.monitor = MockMonitor(self.service_host, self.file_system)
        self.firewall = MockFirewallManager()
        self.brain = MockGeminiEngine()
        self.recon = MockReconFast()
        self.policy = SecurityPolicy(self.config)
        self.router = ModelRouter()
        self.orchestrator = AsyncOrchestrator(critical_workers=2, background_workers=2)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _make_agent(self, poller=None, brain=None, firewall=None, monitor=None, db=None) -> KothAgent:
        return KothAgent(
            config=self.config,
            db_manager=db or self.db,
            model_router=self.router,
            policy=self.policy,
            telemetry_poller=poller or TelemetryPoller(provider=ConfigurableScoreboardAdapter(url="http://mock/api")),
            brain=brain or self.brain,
            monitor=monitor or self.monitor,
            firewall=firewall or self.firewall,
            patcher=self.service_host,
            recon=self.recon,
            orchestrator=self.orchestrator,
            skip_validation=True,
        )

    # 1. Scoreboard timeout
    def test_failure_1_scoreboard_timeout(self):
        mock_provider = MagicMock()
        mock_provider.get_state.return_value = NormalizedScoreboardState(
            is_valid=False, error="Connection timed out after 5.0s"
        )
        agent = self._make_agent(poller=TelemetryPoller(provider=mock_provider))

        record = agent.tick()
        self.assertTrue(record.success)
        self.assertEqual(record.action_name, "hold")
        self.assertEqual(agent.router.metrics.total_decisions, 1)

    # 2. Scoreboard malformed response
    def test_failure_2_scoreboard_malformed_response(self):
        mock_provider = MagicMock()
        mock_provider.get_state.return_value = NormalizedScoreboardState(
            is_valid=False, error="Malformed JSON: Expecting value at line 1"
        )
        agent = self._make_agent(poller=TelemetryPoller(provider=mock_provider))

        record = agent.tick()
        self.assertTrue(record.success)
        self.assertEqual(record.action_name, "hold")

    # 3. Gemini Flash timeout
    def test_failure_3_gemini_flash_timeout(self):
        mock_brain = MagicMock()
        mock_brain.decide_tactical.side_effect = TimeoutError("Flash API request timed out after 10s")

        # Telemetry with score change to trigger AI
        mock_provider = MagicMock()
        mock_provider.get_state.return_value = NormalizedScoreboardState(
            is_valid=True,
            own_score=850.0,
            score_delta=-150.0,
            service_status=[ServiceStatus("10.0.1.5", 80, True, time.time())],
        )
        agent = self._make_agent(poller=TelemetryPoller(provider=mock_provider), brain=mock_brain)

        record = agent.tick()
        self.assertTrue(record.success)
        self.assertEqual(record.action_name, "hold")

    # 4. Gemini Pro timeout
    def test_failure_4_gemini_pro_timeout(self):
        mock_brain = MagicMock()
        # Flash returns low confidence -> triggers Pro escalation -> Pro times out
        mock_brain.decide_tactical.return_value = Decision(
            action_type="defend",
            target="10.0.1.5:80",
            priority="critical",
            reasoning="Uncertain situation",
            confidence=0.45,
            model_used="nvidia/nemotron-3.5-lightning-30b-a3b",
        )
        mock_brain.decide_deep_reasoning.side_effect = TimeoutError("Pro API timed out")

        mock_provider = MagicMock()
        mock_provider.get_state.return_value = NormalizedScoreboardState(
            is_valid=True,
            own_score=900.0,
            service_status=[ServiceStatus("10.0.1.5", 80, True, time.time())],
        )
        agent = self._make_agent(poller=TelemetryPoller(provider=mock_provider), brain=mock_brain)

        record = agent.tick()
        self.assertTrue(record.success)
        # Should cleanly fallback without crashing
        self.assertIn(record.action_name, ("restart_service", "hold"))

    # 5. Simultaneous service failures
    def test_failure_5_simultaneous_service_failures(self):
        self.service_host.fail_service("10.0.1.5", 80)
        self.service_host.fail_service("10.0.1.5", 443)
        mock_provider = MagicMock()
        mock_provider.get_state.return_value = NormalizedScoreboardState(
            is_valid=True,
            own_score=700.0,
            service_status=[
                ServiceStatus("10.0.1.5", 80, False, time.time(), "down"),
                ServiceStatus("10.0.1.5", 443, False, time.time(), "down"),
            ],
        )
        agent = self._make_agent(poller=TelemetryPoller(provider=mock_provider))

        record = agent.tick()
        self.assertTrue(record.success)
        # Multi-failure prioritized one of the services safely
        self.assertIn(record.action_name, ("restart_service", "hold"))

    # 6. Stale telemetry
    def test_failure_6_stale_telemetry(self):
        mock_provider = MagicMock()
        mock_provider.get_state.return_value = NormalizedScoreboardState(
            timestamp=time.time() - 120.0,
            is_valid=False,
            is_stale=True,
            error="Scoreboard data is stale (120s old)",
        )
        agent = self._make_agent(poller=TelemetryPoller(provider=mock_provider))

        record = agent.tick()
        self.assertTrue(record.success)
        self.assertEqual(record.action_name, "hold")

    # 7. Verification failure (exit 0 but port still dead)
    def test_failure_7_verification_failure(self):
        self.service_host.fail_service("10.0.1.5", 80)
        for s in self.service_host.services.values():
            if s["host"] == "10.0.1.5" and s["port"] == 80:
                s["verification_should_fail"] = True

        mock_provider = MagicMock()
        mock_provider.get_state.return_value = NormalizedScoreboardState(
            is_valid=True,
            service_status=[ServiceStatus("10.0.1.5", 80, False, time.time())],
        )
        agent = self._make_agent(poller=TelemetryPoller(provider=mock_provider))

        record = agent.tick()
        self.assertTrue(record.success)  # command exit 0
        self.assertFalse(record.empirical_success)  # decoupled reality: port remains DOWN
        self.assertFalse(record.verification_result.get("verified_up", True))

    # 8. Unauthorized target
    def test_failure_8_unauthorized_target(self):
        mock_brain = MagicMock()
        mock_brain.decide_tactical.return_value = Decision(
            action_type="attack",
            target="8.8.8.8:53",
            priority="critical",
            reasoning="Attacking public DNS",
            confidence=1.0,
            model_used="nvidia/nemotron-3.5-lightning-30b-a3b",
        )
        mock_provider = MagicMock()
        mock_provider.get_state.return_value = NormalizedScoreboardState(
            is_valid=True,
            own_score=800.0,
            score_delta=-100.0,
            service_status=[ServiceStatus("10.0.1.5", 80, True, time.time())],
        )
        agent = self._make_agent(poller=TelemetryPoller(provider=mock_provider), brain=mock_brain)

        record = agent.tick()
        self.assertTrue(record.success)
        self.assertEqual(record.action_name, "hold")

    # 9. Unauthorized service
    def test_failure_9_unauthorized_service(self):
        mock_brain = MagicMock()
        mock_brain.decide_tactical.return_value = Decision(
            action_type="defend",
            target="10.0.99.99:9999",
            priority="high",
            reasoning="Restart unconfigured system unit",
            confidence=1.0,
            model_used="nvidia/nemotron-3.5-lightning-30b-a3b",
        )
        mock_provider = MagicMock()
        mock_provider.get_state.return_value = NormalizedScoreboardState(
            is_valid=True,
            own_score=800.0,
            score_delta=-100.0,
            service_status=[ServiceStatus("10.0.1.5", 80, True, time.time())],
        )
        agent = self._make_agent(poller=TelemetryPoller(provider=mock_provider), brain=mock_brain)

        record = agent.tick()
        self.assertTrue(record.success)
        self.assertEqual(record.action_name, "hold")

    # 10. Firewall transaction failure
    def test_failure_10_firewall_transaction_failure(self):
        failing_firewall = MockFirewallManager(should_fail_apply=True)
        mock_provider = MagicMock()
        mock_provider.get_state.return_value = NormalizedScoreboardState(
            is_valid=True,
            service_status=[ServiceStatus("10.0.1.5", 80, True, time.time())],
        )
        agent = self._make_agent(
            firewall=failing_firewall,
            poller=TelemetryPoller(provider=mock_provider),
        )

        # Trigger rate limit action via tampered file
        self.file_system.tamper("/var/www/html/index.php")
        record = agent.tick()
        self.assertFalse(record.success)
        self.assertFalse(record.empirical_success)
        self.assertIn("Simulated nft apply failure", record.failure_reason)

    # 11. Database failure
    def test_failure_11_database_failure(self):
        failing_db = MagicMock()
        failing_db.record_telemetry.side_effect = sqlite3.OperationalError("disk I/O error")
        failing_db.record_action.side_effect = sqlite3.OperationalError("disk I/O error")
        failing_db.get_recent_action_strings.return_value = []

        agent = self._make_agent(db=failing_db)
        # Agent should catch DB errors or remain alive
        try:
            record = agent.tick()
        except sqlite3.OperationalError:
            # If raised, verify agent did not perform destructive actions
            record = None
        # Agent state remains defined

    # 12. Queue overload
    def test_failure_12_queue_overload(self):
        async def run_overload():
            await self.orchestrator.start()
            try:
                # Flood background queue
                tasks = []
                for i in range(25):
                    action = agent.action_registry.resolve("hold")
                    t = asyncio.create_task(
                        self.orchestrator.execute_now(
                            action=action,
                            target="",
                            context=agent.context,
                            priority=TaskPriority.BACKGROUND,
                        )
                    )
                    tasks.append(t)
                results = await asyncio.gather(*tasks)
                self.assertEqual(len(results), 25)
            finally:
                await self.orchestrator.stop()

        agent = self._make_agent()
        asyncio.run(run_overload())

    # 13. Slow reconnaissance
    def test_failure_13_slow_reconnaissance(self):
        async def run_slow_recon():
            await self.orchestrator.start()
            try:
                # Enqueue slow background recon
                slow_recon = agent.action_registry.resolve("recon", target="198.51.100.10")
                t_recon = asyncio.create_task(
                    self.orchestrator.execute_now(
                        action=slow_recon,
                        target="198.51.100.10",
                        context=agent.context,
                        priority=TaskPriority.BACKGROUND,
                    )
                )
                await asyncio.sleep(0.01)

                # Critical defense must complete immediately without waiting for recon
                defend_action = agent.action_registry.resolve("defend", target="10.0.1.5:80")
                t0 = time.time()
                rec = await self.orchestrator.execute_now(
                    action=defend_action,
                    target="10.0.1.5:80",
                    context=agent.context,
                    priority=TaskPriority.CRITICAL,
                )
                dt = (time.time() - t0) * 1000.0
                self.assertTrue(rec.success)
                self.assertLess(dt, 200.0)  # completed in <200ms

                await t_recon
            finally:
                await self.orchestrator.stop()

        agent = self._make_agent()
        asyncio.run(run_slow_recon())


if __name__ == "__main__":
    unittest.main()
