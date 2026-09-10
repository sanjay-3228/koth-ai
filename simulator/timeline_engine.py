"""Timeline engine driving the deterministic competition round (Scenario 14).

Timeline Events:
- T+00: Everything healthy.
- T+10: Own web service fails.
- T+12: Score decreases.
- T+15: Background recon starts.
- T+16: Second service fails.
- T+17: Integrity event occurs.
- T+20: Fast provider becomes unavailable.
- T+25: System recovers.
"""
import asyncio
import time
from typing import Any, Callable, Dict, List, Optional

from agent.actions.attack_actions import ReconScanAction
from agent.actions.base import ActionExecutionRecord
from agent.async_orchestrator import TaskPriority
from agent.config import Config
from agent.main import KothAgent
from .metrics_collector import MetricsCollector
from .mock_environment import (
    MockFileSystem,
    MockFirewallManager,
    MockGeminiEngine,
    MockMonitor,
    MockScoreboardServer,
    MockServiceHost,
)


class TimelineEngine:
    def __init__(
        self,
        config: Config,
        metrics: MetricsCollector,
        time_step_delay: float = 0.05,  # accelerated execution for fast testing
    ):
        self.config = config
        self.metrics = metrics
        self.time_step_delay = time_step_delay

        # Initialize mock environment components
        self.scoreboard = MockScoreboardServer()
        self.service_host = MockServiceHost()
        self.file_system = MockFileSystem()
        self.monitor = MockMonitor(self.service_host, self.file_system)
        self.firewall = MockFirewallManager(dry_run=True)
        self.gemini = MockGeminiEngine()

        from agent.attack.recon import HostFingerprint
        class MockRecon:
            def scan(self, host: str, ports: str = "1-1024"):
                return HostFingerprint(host=host, open_ports=[80, 443])
        self.recon = MockRecon()

        # Initialize KothAgent with mocks injected
        self.agent = KothAgent(
            config=self.config if hasattr(self, 'config') else None,
            telemetry_poller=self.scoreboard,
            brain=self.gemini,
            monitor=self.monitor,
            firewall=self.firewall,
            patcher=self.service_host,
            recon=self.recon,
            skip_validation=True,
        )

        self.timeline_log: List[Dict[str, Any]] = []

    async def run_round(self) -> Dict[str, Any]:
        """Execute the deterministic competition round from T=0 to T=25."""
        round_start = time.time()
        recon_task_future = None

        # Start orchestrator for async background tasks
        await self.agent.orchestrator.start()

        try:
            for t in range(26):
                step_start = time.time()
                events_in_step = []

                # T+00: Everything healthy
                if t == 0:
                    self.scoreboard.set_state("healthy")
                    events_in_step.append("T+00: Initial state - All services UP, files clean.")

                # T+10: Own web service fails
                elif t == 10:
                    self.service_host.fail_service("10.0.1.5", 80)
                    self.scoreboard.set_state("service_down")
                    events_in_step.append("T+10: Own web-service (10.0.1.5:80) FAILED.")

                # T+12: Score decreases
                elif t == 12:
                    self.scoreboard.set_state("score_decrease")
                    events_in_step.append("T+12: Score decreased from 1000 to 850 (Rank dropped to 3).")

                # T+15: Background recon starts
                elif t == 15:
                    events_in_step.append("T+15: Long-running background recon task dispatched.")
                    recon_task_future = self.agent.orchestrator.enqueue(
                        action=ReconScanAction(),
                        target="198.51.100.10",
                        context=self.agent.context,
                        priority=TaskPriority.BACKGROUND,
                    )

                # T+16: Second service fails (both services now down simultaneously)
                elif t == 16:
                    self.service_host.fail_service("10.0.1.5", 80)
                    self.service_host.fail_service("10.0.1.5", 443)
                    self.scoreboard.set_state("multiple_services_down")
                    events_in_step.append("T+16: Second service nginx-ssl (10.0.1.5:443) FAILED (multiple services down).")

                # T+17: Integrity event occurs
                elif t == 17:
                    self.file_system.tamper("/var/www/html/index.php")
                    events_in_step.append("T+17: File tampering detected on /var/www/html/index.php.")

                # T+20: Fast provider becomes unavailable
                elif t == 20:
                    self.gemini.flash_available = False
                    events_in_step.append("T+20: Fast provider timeout/unavailable.")

                # T+25: System recovers
                elif t == 25:
                    self.service_host.recover_service("10.0.1.5", 80)
                    self.service_host.recover_service("10.0.1.5", 443)
                    self.file_system.restore("/var/www/html/index.php")
                    self.gemini.flash_available = True
                    self.scoreboard.set_state("healthy")
                    events_in_step.append("T+25: System state restored to healthy.")

                # Agent tick execution
                t_detect_start = time.time()
                telemetry = self.scoreboard.fetch()
                snapshot = self.monitor.full_snapshot(self.agent.context.config.own_services)
                detection_latency_ms = (time.time() - t_detect_start) * 1000

                t_decision_start = time.time()
                decision = self.agent.router.execute_decision(
                    telemetry=telemetry,
                    telemetry_summary=self.agent._summarize_telemetry(telemetry),
                    recent_actions=self.agent.action_log,
                    brain=self.gemini,
                    monitor_snapshot=snapshot,
                )
                decision_latency_ms = (time.time() - t_decision_start) * 1000

                # Authorize
                auth = self.agent.security_policy.authorize(decision)
                effective_decision = auth.safe_decision if not auth.allowed else decision

                # Resolve and execute action
                action = self.agent.action_registry.resolve(
                    action_type=effective_decision.action_type,
                    target=effective_decision.target,
                    details=effective_decision.reasoning,
                )

                t_action_start = time.time()
                record: ActionExecutionRecord = action.execute(
                    target=effective_decision.target,
                    context=self.agent.context,
                    model_used=effective_decision.model_used,
                    model_confidence=effective_decision.confidence,
                )
                action_latency_ms = (time.time() - t_action_start) * 1000

                # Record verification
                verification_latency_ms = 1.2
                self.metrics.record_decision(
                    model_used=effective_decision.model_used,
                    confidence=effective_decision.confidence,
                    latency_ms=decision_latency_ms,
                )
                self.metrics.record_action_outcome(
                    success=record.success,
                    empirical_success=record.empirical_success,
                    is_security_block=(not auth.allowed),
                )

                step_duration_ms = (time.time() - step_start) * 1000
                self.timeline_log.append({
                    "second": t,
                    "events": events_in_step,
                    "model_used": effective_decision.model_used,
                    "action_type": effective_decision.action_type,
                    "target": effective_decision.target,
                    "empirical_success": record.empirical_success,
                    "duration_ms": round(step_duration_ms, 2),
                    "detection_ms": round(detection_latency_ms, 2),
                    "decision_ms": round(decision_latency_ms, 2),
                    "action_ms": round(action_latency_ms, 2),
                })

                if self.time_step_delay > 0:
                    await asyncio.sleep(self.time_step_delay)

            # Await background recon completion if running
            if recon_task_future and not recon_task_future.done():
                await asyncio.wait_for(recon_task_future, timeout=5.0)

        finally:
            await self.agent.orchestrator.stop()

        total_round_duration_s = time.time() - round_start
        return {
            "duration_s": round(total_round_duration_s, 2),
            "timeline_steps": len(self.timeline_log),
            "summary": self.metrics.get_summary(),
        }
