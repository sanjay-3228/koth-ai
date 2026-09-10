"""Unit tests for the AsyncOrchestrator priority queue, worker isolation, and action verification."""
import asyncio
import time
import unittest
from unittest.mock import MagicMock

from agent.actions.attack_actions import ExploitPluginAction, ReconScanAction
from agent.actions.base import ActionContext, ActionExecutionRecord, BaseAction
from agent.actions.defense_actions import RestartServiceAction
from agent.actions.hold_action import HoldAction
from agent.async_orchestrator import AsyncOrchestrator, TaskPriority
from agent.attack.dispatcher import PluginDispatcher
from agent.attack.plugin_interface import ExploitPlugin, ExploitResult
from agent.attack.recon import HostFingerprint
from agent.config import Config


class SlowMockReconAction(BaseAction):
    """Simulates a 0.25-second slow background recon scan."""
    action_name = "slow_recon"
    action_type = "recon"

    def __init__(self):
        self.started_time = None
        self.finished_time = None

    def execute(self, target: str, context: ActionContext, model_used: str = "", model_confidence: float = 1.0) -> ActionExecutionRecord:
        self.started_time = time.time()
        time.sleep(0.2)
        self.finished_time = time.time()
        return ActionExecutionRecord(
            action_name=self.action_name,
            action_type=self.action_type,
            target=target,
            success=True,
            empirical_success=True,
            verification_result={"ports": [80, 443]},
        )

    def verify(self, target: str, context: ActionContext, record: ActionExecutionRecord):
        return {"verified": True}


class FastCriticalDefenseAction(BaseAction):
    """Simulates an immediate critical service recovery action."""
    action_name = "fast_recovery"
    action_type = "defend"

    def __init__(self):
        self.started_time = None
        self.finished_time = None

    def execute(self, target: str, context: ActionContext, model_used: str = "", model_confidence: float = 1.0) -> ActionExecutionRecord:
        self.started_time = time.time()
        time.sleep(0.01)
        self.finished_time = time.time()
        return ActionExecutionRecord(
            action_name=self.action_name,
            action_type=self.action_type,
            target=target,
            success=True,
            empirical_success=True,
            verification_result={"verified_up": True},
        )

    def verify(self, target: str, context: ActionContext, record: ActionExecutionRecord):
        return {"verified_up": True}


class TestAsyncOrchestration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.config = Config(
            gemini_api_key="mock",
            scoreboard_url="http://mock",
            own_services=["10.0.1.5:80:web-service"],
            target_hosts=["192.168.10.50"],
            allowed_plugins=["allowed_exploit"],
            dry_run=True,
        )
        self.context = ActionContext(
            config=self.config,
            monitor=MagicMock(),
            firewall=MagicMock(),
            patcher=MagicMock(),
            recon=MagicMock(),
            dispatcher=MagicMock(),
        )
        self.orchestrator = AsyncOrchestrator(critical_workers=2, background_workers=2)
        await self.orchestrator.start()

    async def asyncTearDown(self):
        await self.orchestrator.stop()

    async def test_critical_recovery_never_blocks_behind_slow_recon(self):
        """Proof: Dedicated critical workers ensure critical recovery finishes before a slow recon task."""
        slow_recon = SlowMockReconAction()
        fast_defense = FastCriticalDefenseAction()

        # Enqueue slow recon first in BACKGROUND priority
        recon_fut = self.orchestrator.enqueue(
            action=slow_recon,
            target="192.168.10.50",
            context=self.context,
            priority=TaskPriority.BACKGROUND,
        )

        # Give the event loop a tiny fraction of a second to let recon worker pick it up
        await asyncio.sleep(0.01)

        # Now enqueue critical recovery in CRITICAL priority
        defense_fut = self.orchestrator.enqueue(
            action=fast_defense,
            target="10.0.1.5:80",
            context=self.context,
            priority=TaskPriority.CRITICAL,
        )

        # Await the defense future
        defense_rec = await defense_fut

        # The defense task MUST finish while the recon task is still running
        self.assertTrue(defense_rec.success)
        self.assertIsNotNone(fast_defense.finished_time)
        self.assertFalse(recon_fut.done(), "Recon completed prematurely; defense did not preempt/run concurrently!")

        # Await the remaining recon task
        recon_rec = await recon_fut
        self.assertTrue(recon_rec.success)
        self.assertGreater(slow_recon.finished_time, fast_defense.finished_time)

    async def test_action_verification_record_structure(self):
        """Proof: Executing an action produces a fully populated ActionExecutionRecord."""
        hold = HoldAction()
        record = await self.orchestrator.execute_now(
            action=hold,
            target="",
            context=self.context,
            priority=TaskPriority.NORMAL,
            model_used="nvidia/nemotron-3.5-lightning-30b-a3b",
            model_confidence=0.92,
        )

        self.assertIsInstance(record, ActionExecutionRecord)
        self.assertEqual(record.action_name, "hold")
        self.assertEqual(record.action_type, "hold")
        self.assertEqual(record.model_used, "nvidia/nemotron-3.5-lightning-30b-a3b")
        self.assertEqual(record.model_confidence, 0.92)
        self.assertTrue(record.attempted)
        self.assertTrue(record.success)
        self.assertTrue(record.empirical_success)
        self.assertIn("hold_active", record.verification_result)
        self.assertGreater(record.completed_at, record.started_at - 0.001)

    def test_plugin_dispatcher_allowlist_enforcement(self):
        """Proof: Dispatcher strictly refuses plugins not in allowed_plugins allowlist."""
        dispatcher = PluginDispatcher(allowed_plugins=["allowed_exploit"])

        class UnapprovedPlugin(ExploitPlugin):
            name = "unapproved_backdoor"
            matches_service = "http"

            def run(self, host: str, port: int, context: dict) -> ExploitResult:
                return ExploitResult(success=True, notes="Executed unapproved payload")

        dispatcher.register(UnapprovedPlugin())

        cfg = Config(
            gemini_api_key="mock",
            scoreboard_url="http://mock",
            target_hosts=["192.168.10.50"],
            allowed_plugins=["allowed_exploit"],
            dry_run=True,
        )

        fp = HostFingerprint(host="192.168.10.50", open_ports=[80], services={80: "http"})

        # Dispatch should reject the unapproved plugin
        result = dispatcher.dispatch(fp, 80, context={"safe_param": "val"}, cfg=cfg)
        self.assertIsNone(result, "Dispatcher executed an unapproved plugin not in allowed_plugins!")

    def test_plugin_dispatcher_target_host_enforcement(self):
        """Proof: Dispatcher strictly refuses to run against hosts not in TARGET_HOSTS."""
        dispatcher = PluginDispatcher(allowed_plugins=["allowed_exploit"])

        class ApprovedPlugin(ExploitPlugin):
            name = "allowed_exploit"
            matches_service = "http"

            def run(self, host: str, port: int, context: dict) -> ExploitResult:
                return ExploitResult(success=True, notes="Executed on target")

        dispatcher.register(ApprovedPlugin())

        cfg = Config(
            gemini_api_key="mock",
            scoreboard_url="http://mock",
            target_hosts=["192.168.10.50"],
            allowed_plugins=["allowed_exploit"],
            dry_run=True,
        )

        # Fingerprint points to unauthorized host 10.99.99.99
        fp = HostFingerprint(host="10.99.99.99", open_ports=[80], services={80: "http"})

        result = dispatcher.dispatch(fp, 80, context={}, cfg=cfg)
        self.assertIsNone(result, "Dispatcher executed plugin against unauthorized target host!")

    def test_plugin_dispatcher_context_sanitization(self):
        """Proof: Dispatcher strips sensitive keys (e.g. API keys, secrets) before passing context to plugins."""
        dispatcher = PluginDispatcher(allowed_plugins=["allowed_exploit"])
        received_context = {}

        class ApprovedPlugin(ExploitPlugin):
            name = "allowed_exploit"
            matches_service = "http"

            def run(self, host: str, port: int, context: dict) -> ExploitResult:
                received_context.update(context)
                return ExploitResult(success=True, notes="Executed")

        dispatcher.register(ApprovedPlugin())

        cfg = Config(
            gemini_api_key="secret_gemini_key_12345",
            scoreboard_url="http://mock",
            target_hosts=["192.168.10.50"],
            allowed_plugins=["allowed_exploit"],
            dry_run=True,
        )

        fp = HostFingerprint(host="192.168.10.50", open_ports=[80], services={80: "http"})

        malicious_context = {
            "api_key": "leak_me",
            "gemini_api_key": "secret",
            "password": "pass",
            "token": "tok",
            "safe_tag": "comp_round_1",
        }

        dispatcher.dispatch(fp, 80, context=malicious_context, cfg=cfg)

        # Verify sensitive keys were removed
        self.assertNotIn("api_key", received_context)
        self.assertNotIn("gemini_api_key", received_context)
        self.assertNotIn("password", received_context)
        self.assertNotIn("token", received_context)
        self.assertIn("host", received_context)


if __name__ == "__main__":
    unittest.main()
