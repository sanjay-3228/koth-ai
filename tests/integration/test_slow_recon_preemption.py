"""Integration Test - Scenario 5: Slow Reconnaissance Preemption."""
import asyncio
import time
import unittest

from agent.actions.base import ActionContext, ActionExecutionRecord, BaseAction
from agent.actions.defense_actions import RestartServiceAction
from agent.async_orchestrator import TaskPriority
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


class Simulated30sReconAction(BaseAction):
    """Simulates a slow background recon job that takes noticeable time."""
    action_name = "simulated_slow_recon"
    action_type = "recon"

    def __init__(self, duration_s: float = 0.3):
        self.duration_s = duration_s
        self.started_at = 0.0
        self.finished_at = 0.0

    def execute(self, target: str, context: ActionContext, model_used: str = "", model_confidence: float = 1.0) -> ActionExecutionRecord:
        self.started_at = time.time()
        time.sleep(self.duration_s)
        self.finished_at = time.time()
        return ActionExecutionRecord(
            action_name=self.action_name,
            action_type=self.action_type,
            target=target,
            success=True,
            empirical_success=True,
            started_at=self.started_at,
            completed_at=self.finished_at,
            verification_result={"ports": [80, 443, 8080]},
        )

    def verify(self, target: str, context: ActionContext, record: ActionExecutionRecord):
        return {"verified": True}


class TestSlowReconPreemptionIntegration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
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
        await self.agent.orchestrator.start()

    async def asyncTearDown(self):
        await self.agent.orchestrator.stop()

    async def test_slow_recon_does_not_delay_critical_recovery(self):
        """Simulate slow recon in background queue and prove critical service recovery runs without waiting."""
        slow_recon = Simulated30sReconAction(duration_s=0.25)

        # 1. Enqueue slow recon into BACKGROUND queue
        t_recon_enqueued = time.time()
        recon_future = self.agent.orchestrator.enqueue(
            action=slow_recon,
            target="198.51.100.10",
            context=self.agent.context,
            priority=TaskPriority.BACKGROUND,
        )

        # Allow background worker to pick up recon
        await asyncio.sleep(0.01)

        # 2. Critical failure occurs on own web service
        self.service_host.fail_service("10.0.1.5", 80)
        self.scoreboard.set_state("service_down")

        # 3. Enqueue CRITICAL defense recovery
        t_defense_enqueued = time.time()
        defense_future = self.agent.orchestrator.enqueue(
            action=RestartServiceAction(),
            target="10.0.1.5:80",
            context=self.agent.context,
            priority=TaskPriority.CRITICAL,
        )

        # 4. Await defense recovery
        defense_record = await defense_future
        t_defense_finished = time.time()

        # The defense task MUST finish while recon is still executing
        self.assertTrue(defense_record.success)
        self.assertTrue(defense_record.empirical_success)
        self.assertFalse(recon_future.done(), "Recon completed prematurely; defense did not run concurrently!")

        # Defense latency must be significantly less than the slow recon duration
        defense_wait_time = t_defense_finished - t_defense_enqueued
        self.assertLess(defense_wait_time, 0.1)

        # 5. Await recon task completion
        recon_record = await recon_future
        self.assertTrue(recon_record.success)
        self.assertGreater(slow_recon.finished_at, t_defense_finished)


if __name__ == "__main__":
    unittest.main()
