"""The agent's main loop and orchestration coordinator.

Coordinates:
  1. Pull fresh telemetry from scoreboard.
  2. Collect local service/integrity state via ServiceMonitor.full_snapshot.
  3. Route decision through ModelRouter (Local Policy -> Flash -> Pro Preview).
  4. Pass decision through SecurityPolicy authorization gate (OWN_SERVICES vs TARGET_HOSTS).
  5. Execute via typed ActionRegistry handlers.
  6. Independently verify post-action system state and record empirical success metrics.
  7. Persist to SQLite and repeat.
"""
import asyncio
import time
from typing import Any, List, Optional

from .actions.base import ActionContext, ActionExecutionRecord
from .actions.registry import ActionRegistry, action_registry
from .async_orchestrator import AsyncOrchestrator, TaskPriority
from .attack.dispatcher import PluginDispatcher
from .attack.recon import ReconScanner
from .config import Config, config as global_config
from .db import DatabaseManager, db
from .defense.firewall import FirewallManager
from .defense.monitor import ServiceMonitor
from .defense.patcher import ServicePatcher
from .nvidia_client import NvidiaDecisionEngine, GeminiDecisionEngine
from .logger import get_logger, setup_logging
from .model_router import ModelRouter, router
from .security.execution_gate import FinalExecutionGate
from .security.policy import AuthorizationResult, SecurityPolicy, security_policy
from .security.safety_gates import SafetyGateError, SafetyGateManager
from .telemetry import TelemetryPoller

logger = get_logger(__name__)


class KothAgent:
    def __init__(
        self,
        config: Optional[Config] = None,
        db_manager: Optional[DatabaseManager] = None,
        model_router: Optional[ModelRouter] = None,
        policy: Optional[SecurityPolicy] = None,
        registry: Optional[ActionRegistry] = None,
        telemetry_poller: Optional[TelemetryPoller] = None,
        brain: Optional[Any] = None,
        monitor: Optional[ServiceMonitor] = None,
        firewall: Optional[FirewallManager] = None,
        patcher: Optional[ServicePatcher] = None,
        recon: Optional[ReconScanner] = None,
        dispatcher: Optional[PluginDispatcher] = None,
        orchestrator: Optional[AsyncOrchestrator] = None,
        skip_validation: bool = False,
        swarm_client: Optional[Any] = None,
    ):
        self.config = config or global_config
        self.swarm_client = swarm_client
        self.safety_gates = SafetyGateManager(self.config)
        if not skip_validation:
            self.config.validate()
            self.safety_gates.validate_for_start()
        if telemetry_poller is not None:
            self.telemetry_poller = telemetry_poller
        else:
            # TelemetryPoller initialized from active configuration.
            self.telemetry_poller = TelemetryPoller()
        self.brain = brain or NvidiaDecisionEngine()
        self.monitor = monitor or ServiceMonitor()
        self.firewall = firewall or FirewallManager()
        self.patcher = patcher or ServicePatcher()
        self.recon = recon or ReconScanner()
        self.dispatcher = dispatcher or PluginDispatcher(allowed_plugins=self.config.allowed_plugins)
        self.db = db_manager or db
        self.router = model_router or router
        if hasattr(self.router, "db") and self.router.db is None:
            self.router.db = self.db
        self.security_policy = policy or (SecurityPolicy(self.config) if config else security_policy)
        self.action_registry = registry or action_registry
        self.execution_gate = FinalExecutionGate(
            config=self.config,
            security_policy=self.security_policy,
            action_registry=self.action_registry,
        )
        self.orchestrator = orchestrator or AsyncOrchestrator()

        self.context = ActionContext(
            config=self.config,
            monitor=self.monitor,
            firewall=self.firewall,
            patcher=self.patcher,
            recon=self.recon,
            dispatcher=self.dispatcher,
            db=self.db,
        )

        # Pre-load recent actions from persistence layer so history survives restarts
        self.action_log: List[str] = self.db.get_recent_action_strings(limit=20)
        logger.info(
            "KothAgent initialized. Preloaded %d historical action(s) from database. Fast: %s | Reasoning: %s | Specialist: %s",
            len(self.action_log),
            self.config.nvidia_fast_model,
            self.config.groq_reasoning_model,
            self.config.openrouter_specialist_model,
        )

    def _summarize_telemetry(self, telemetry) -> str:
        if not telemetry:
            return "telemetry=unavailable"
        raw = getattr(telemetry, "raw", {}) or {}
        lines = [
            f"profile={raw.get('profile', self.config.lab_profile)}",
            f"target={raw.get('target', '')}",
            f"reachable={raw.get('reachable', raw.get('telemetry_status', 'unknown'))}",
            f"open_ports={raw.get('open_ports', [])}",
            f"our_score={getattr(telemetry, 'our_score', 0.0)}",
            f"rank={getattr(telemetry, 'rank', 'unknown')}",
        ]
        for svc in getattr(telemetry, "our_services", []):
            status = "UP" if getattr(svc, "up", False) else "DOWN"
            lines.append(f"  service {getattr(svc, 'host', '')}:{getattr(svc, 'port', 0)} -> {status} {getattr(svc, 'note', '')}")
        for name, score in getattr(telemetry, "competitor_scores", {}).items():
            lines.append(f"  competitor {name}: {score}")
        return "\n".join(lines)

    def tick(self) -> ActionExecutionRecord:
        """Execute one complete synchronized agent cycle."""
        # 0. Kill switch check
        if self.safety_gates.is_kill_switch_engaged():
            logger.warning("[KILL SWITCH] Kill switch is engaged! Reverting immediately to safe hold.")
            record = ActionExecutionRecord(
                action_type="hold",
                action_name="hold",
                target="",
                model_used="kill-switch",
                started_at=time.time(),
                completed_at=time.time(),
                success=True,
                empirical_success=True,
                verification_result={"state": "kill_switch_engaged", "hold_active": True},
            )
            record.build_dry_run_record(authorized=True)
            return record

        # 0b. Swarm phase synchronization & HOLD gate
        if self.swarm_client:
            self.swarm_client.sync_phase()
            self.swarm_client.send_heartbeat()
            if self.swarm_client.current_phase.value in ("HOLD", "UNKNOWN") or getattr(self.swarm_client.status, "value", "") == "SAFE_DEGRADED":
                logger.info(f"[SWARM] Swarm mode HOLD active (phase={self.swarm_client.current_phase.value}, status={getattr(self.swarm_client.status, 'value', 'unknown')}). Forcing safe hold cycle.")
                record = ActionExecutionRecord(
                    action_type="hold",
                    action_name="hold",
                    target="",
                    model_used="swarm-phase-gate",
                    started_at=time.time(),
                    completed_at=time.time(),
                    success=True,
                    empirical_success=True,
                    verification_result={"state": "swarm_hold_active", "phase": self.swarm_client.current_phase.value},
                )
                record.build_dry_run_record(authorized=True)
                return record

        # 1. Pull telemetry and record
        telemetry = self.telemetry_poller.fetch()
        self.db.record_telemetry(telemetry)

        # 2. Collect local monitor snapshot (file integrity + host/port reachability)
        monitor_snapshot = self.monitor.full_snapshot(self.config.own_services)

        # 3. Model routing: Local policy -> NVIDIA Nemotron -> Groq GPT-OSS 120B -> OpenRouter GLM 5.3 Flash
        summary = self._summarize_telemetry(telemetry)
        swarm_ctx = None
        if self.swarm_client:
            swarm_ctx = {
                "phase": getattr(self.swarm_client.current_phase, "value", "HOLD"),
                "agent_id": getattr(self.swarm_client, "agent_id", self.config.agent_id),
                "team_id": getattr(self.swarm_client, "team_id", self.config.team_id),
                "round_id": getattr(self.swarm_client, "current_round", 1),
                "phase_epoch": getattr(self.swarm_client, "phase_epoch", 1),
            }
        decision = self.router.execute_decision(
            telemetry=telemetry,
            telemetry_summary=summary,
            recent_actions=self.action_log,
            brain=self.brain,
            monitor_snapshot=monitor_snapshot,
            swarm_context=swarm_ctx,
        )

        logger.info(
            "[decision] [%s] %s target=%s priority=%s confidence=%.2f (%.0fms) — %s",
            decision.model_used,
            decision.action_type,
            decision.target,
            decision.priority,
            decision.confidence,
            decision.latency_ms,
            decision.reasoning,
        )

        # 4. Mandatory Authorization Gate
        auth: AuthorizationResult = self.security_policy.authorize(decision)
        if not auth.allowed:
            logger.warning(
                "[SECURITY REJECTION] Model attempted %s on '%s': %s. Reverted to safe hold.",
                decision.action_type,
                decision.target,
                auth.reason,
            )
            effective_decision = auth.safe_decision or decision
        else:
            effective_decision = decision
            if auth.sanitized_target:
                effective_decision.target = auth.sanitized_target

        # 4b. Rate Limiter check for active actions
        if effective_decision.action_type != "hold":
            if not self.safety_gates.rate_limiter.allow():
                logger.warning(
                    "[RATE LIMIT EXCEEDED] Throttling action %s on '%s' (%d/min exceeded); reverting to safe hold.",
                    effective_decision.action_type,
                    effective_decision.target,
                    self.config.max_actions_per_minute,
                )
                effective_decision.action_type = "hold"
                effective_decision.target = ""
                effective_decision.reasoning = f"Rate limit exceeded ({self.config.max_actions_per_minute}/min); held."

        # 5 & 6. Execute registered action through the final execution authorization gate
        record = self.execution_gate.execute_with_gates(
            decision=effective_decision,
            context=self.context,
            task=getattr(self.swarm_client, "current_task", None) if self.swarm_client else None,
            swarm_client=self.swarm_client,
        )

        # 7. Record verification to model router metrics (empirical success decoupled from model confidence)
        self.router.metrics.record_verification(record.empirical_success)

        # 8. Persist action and verification to SQLite
        action_str = f"{effective_decision.action_type}:{effective_decision.target}:{effective_decision.reasoning}"
        self.action_log.append(action_str)
        self.db.record_action(
            action_type=effective_decision.action_type,
            target=effective_decision.target,
            priority=effective_decision.priority,
            reasoning=effective_decision.reasoning,
            details=record.failure_reason or record.action_name,
            model_used=effective_decision.model_used,
            confidence=effective_decision.confidence,
            latency_ms=effective_decision.latency_ms,
            verification_result=record.verification_result,
            empirical_success=record.empirical_success,
            execution_status="completed" if record.success else "failed",
            authorized=auth.allowed,
            would_execute=(auth.allowed and record.success),
            provider=getattr(effective_decision, "provider", ""),
            fallback_level=getattr(effective_decision, "fallback_level", 0),
            parse_status=getattr(effective_decision, "parse_status", ""),
            request_id=getattr(effective_decision, "request_id", ""),
        )

        # 9. Build structured dry-run record
        dry_rec = record.build_dry_run_record(authorized=auth.allowed)
        if self.config.dry_run:
            logger.info("\n%s", dry_rec.format_log())

        logger.info(
            "[action complete] action=%s target=%s success=%s empirical=%s reason=%s verif=%s",
            record.action_name,
            record.target,
            record.success,
            record.empirical_success,
            record.failure_reason or "none",
            record.verification_result,
        )

        return record

    async def async_tick(self) -> ActionExecutionRecord:
        """Execute one cycle using async priority queues and isolated worker pools."""
        if self.safety_gates.is_kill_switch_engaged():
            logger.warning("[KILL SWITCH] Kill switch is engaged! Reverting immediately to safe hold.")
            record = ActionExecutionRecord(
                action_type="hold",
                action_name="hold",
                target="",
                model_used="kill-switch",
                started_at=time.time(),
                completed_at=time.time(),
                success=True,
                empirical_success=True,
                verification_result={"state": "kill_switch_engaged", "hold_active": True},
            )
            record.build_dry_run_record(authorized=True)
            return record

        telemetry = await asyncio.to_thread(self.telemetry_poller.fetch)
        self.db.record_telemetry(telemetry)

        monitor_snapshot = await asyncio.to_thread(self.monitor.full_snapshot, self.config.own_services)
        summary = self._summarize_telemetry(telemetry)

        decision = await asyncio.to_thread(
            self.router.execute_decision,
            telemetry,
            summary,
            self.action_log,
            self.brain,
            monitor_snapshot,
        )

        auth = self.security_policy.authorize(decision)
        if not auth.allowed:
            effective_decision = auth.safe_decision or decision
        else:
            effective_decision = decision
            if auth.sanitized_target:
                effective_decision.target = auth.sanitized_target

        if effective_decision.action_type != "hold":
            if not self.safety_gates.rate_limiter.allow():
                logger.warning(
                    "[RATE LIMIT EXCEEDED] Throttling action %s on '%s' (%d/min exceeded); reverting to safe hold.",
                    effective_decision.action_type,
                    effective_decision.target,
                    self.config.max_actions_per_minute,
                )
                effective_decision.action_type = "hold"
                effective_decision.target = ""
                effective_decision.reasoning = f"Rate limit exceeded ({self.config.max_actions_per_minute}/min); held."

        action = self.action_registry.resolve(
            action_type=effective_decision.action_type,
            target=effective_decision.target,
            details=effective_decision.reasoning,
        )

        # Map priority string to TaskPriority enum
        if effective_decision.priority == "critical":
            priority = TaskPriority.CRITICAL
        elif effective_decision.priority == "high":
            priority = TaskPriority.HIGH
        elif action.action_name in ("recon_scan", "hold"):
            priority = TaskPriority.BACKGROUND
        else:
            priority = TaskPriority.NORMAL

        record = await self.orchestrator.execute_now(
            action=action,
            target=effective_decision.target,
            context=self.context,
            priority=priority,
            model_used=effective_decision.model_used,
            model_confidence=effective_decision.confidence,
        )

        self.router.metrics.record_verification(record.empirical_success)
        action_str = f"{effective_decision.action_type}:{effective_decision.target}:{effective_decision.reasoning}"
        self.action_log.append(action_str)
        self.db.record_action(
            action_type=effective_decision.action_type,
            target=effective_decision.target,
            priority=effective_decision.priority,
            reasoning=effective_decision.reasoning,
            details=record.failure_reason or action.action_name,
            model_used=effective_decision.model_used,
            confidence=effective_decision.confidence,
            latency_ms=effective_decision.latency_ms,
            verification_result=record.verification_result,
            empirical_success=record.empirical_success,
            execution_status="completed" if record.success else "failed",
            authorized=auth.allowed,
            would_execute=(auth.allowed and record.success),
        )
        dry_rec = record.build_dry_run_record(authorized=auth.allowed)
        if self.config.dry_run:
            logger.info("\n%s", dry_rec.format_log())
        return record

    def run_forever(self) -> None:
        while True:
            try:
                self.tick()
            except Exception as exc:  # keep the loop alive across errors
                logger.error("Tick failed: %s", exc, exc_info=True)
            time.sleep(self.config.tick_interval_seconds)

    async def run_async_forever(self) -> None:
        await self.orchestrator.start()
        try:
            while True:
                try:
                    await self.async_tick()
                except Exception as exc:
                    logger.error("Async tick failed: %s", exc, exc_info=True)
                await asyncio.sleep(self.config.tick_interval_seconds)
        finally:
            await self.orchestrator.stop()


if __name__ == "__main__":
    setup_logging()
    KothAgent().run_forever()
